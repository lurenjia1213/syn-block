#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(internal_features)]
#![feature(core_intrinsics)]

#[allow(unused_imports)]
use core::{
    intrinsics::{likely, unlikely},
    mem,
    mem::size_of,
};

use aya_ebpf::{
    bindings::xdp_action,
    helpers,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap},
    programs::XdpContext,
};
// Conditional logging: enable with `--features ebpf-log` to include `aya-log-ebpf` at compile time.
#[cfg(feature = "ebpf-log")]
pub use aya_log_ebpf::{debug, error, info};

// When the feature is disabled, define no-op macros to avoid runtime cost and unused-variable warnings.
#[cfg(not(feature = "ebpf-log"))]
macro_rules! debug {
    ($ctx:expr, $($arg:tt)*) => {{
        let _ = &$ctx;
    }};
}
#[cfg(not(feature = "ebpf-log"))]
macro_rules! info {
    ($ctx:expr, $($arg:tt)*) => {{
        let _ = &$ctx;
    }};
}
#[cfg(not(feature = "ebpf-log"))]
macro_rules! error {
    ($ctx:expr, $($arg:tt)*) => {{
        let _ = &$ctx;
    }};
}
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SynCounter {
    last_ts: u64,
    count: u64,
    _pad: u32,
}

#[map(name = "PORTS")]
static mut PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(256, 0);

#[map(name = "COUNTERS")]
static mut COUNTERS: LruHashMap<u32, SynCounter> =
    LruHashMap::<u32, SynCounter>::with_max_entries(4096, 0);

#[map(name = "BLOCKED")]
static mut BLOCKED: LruHashMap<u32, u64> = LruHashMap::<u32, u64>::with_max_entries(2048, 0);

#[map(name = "CONFIG")]
static mut CONFIG: Array<u64> = Array::<u64>::with_max_entries(4, 0);

const KEY_WINDOW_NS: u32 = 0; // window seconds in ns stored as u64
const KEY_THRESHOLD: u32 = 1; // threshold stored as u64
const KEY_BLOCK_NS: u32 = 2; // block seconds in ns stored as u64
const KEY_RST: u32 = 3; // whether to send TCP RST when dropping (0/1)

#[inline(always)]
fn parse_ipv4(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn syn_block(ctx: XdpContext) -> u32 {
    match try_syn_block(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_syn_block(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let tcphdr = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                if likely((*tcphdr).syn() != 1 || (*tcphdr).ack() == 1) {
                    //debug!(&ctx, "not tcp syn packet, xdp pass");
                    return Ok(xdp_action::XDP_PASS);
                }
            }
            tcphdr
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
    let _source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let _src_ip_bytes = parse_ipv4(source_addr);

    let now = unsafe { helpers::bpf_ktime_get_ns() } as u64;

    //Originating from user space, it can guarantees these values exist
    let window_ns = unsafe { CONFIG.get(KEY_WINDOW_NS).copied().unwrap_unchecked() };
    let threshold = unsafe { CONFIG.get(KEY_THRESHOLD).copied().unwrap_unchecked() };
    let block_ns = unsafe { CONFIG.get(KEY_BLOCK_NS).copied().unwrap_unchecked() };
    // whether to send TCP RST on drop

    //make ebpf veriflier happy
    let rst_flag_u64 = unsafe { CONFIG.get(KEY_RST).copied().unwrap_or(0) };
    let mut rst_flag = true;
    if rst_flag_u64 == 0 {
        rst_flag = false;
    }

    debug!(
        &ctx,
        "dest_port {}  src_port {} syn packet from src_ip:{}.{}.{}.{}",
        dest_port,
        source_port,
        src_ip_bytes[0],
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3]
    );

    // If blocked and block not expired -> DROP
    if let Some(expire) = unsafe { BLOCKED.get(&source_addr) } {
        if likely(*expire > now) {
            error!(
                &ctx,
                "port {} blocked drop (exp {}s)",
                dest_port,
                (*expire - now) / 1_000_000_000u64
            );

            if rst_flag {
                match send_rst(&ctx, ethhdr, ipv4hdr, tcphdr) {
                    Ok(_) => return Ok(xdp_action::XDP_TX),
                    Err(_) => return Ok(xdp_action::XDP_DROP),
                }
            } else {
                return Ok(xdp_action::XDP_DROP);
            }
        } else {
            // remove expired entry
            unsafe {
                let _ = BLOCKED.remove(&source_addr);
            }
        }
    }
    // check whether this dst port is monitored
    let monitored = unsafe { PORTS.get(&dest_port) };

    if monitored.is_none() {
        debug!(&ctx, "no the monitored port, xdp pass");
        return Ok(xdp_action::XDP_PASS);
    }

    info!(
        &ctx,
        "monitored port {} syn packet from src_ip:{}.{}.{}.{} (window={}s threshold={})",
        dest_port,
        _src_ip_bytes[0],
        _src_ip_bytes[1],
        _src_ip_bytes[2],
        _src_ip_bytes[3],
        window_ns / 1_000_000_000u64,
        threshold
    ); //u32
    // config values already read above

    // update counter: try to modify in-place using get_ptr_mut (Option<*mut>) to reduce map ops
    match unsafe { COUNTERS.get_ptr_mut(&source_addr) } {
        Some(cnt_ptr) => {
            // existing entry: modify in-place via raw pointer
            unsafe {
                let cnt = &mut *cnt_ptr;
                if now - cnt.last_ts <= window_ns {
                    cnt.count = cnt.count.saturating_add(1);
                } else {
                    cnt.count = 1;
                    cnt.last_ts = now;
                }
                if cnt.count >= threshold.saturating_sub(1) {
                    info!(
                        &ctx,
                        "src_ip:{}.{}.{}.{} count={} threshold={} (window={}s)",
                        _src_ip_bytes[0],
                        _src_ip_bytes[1],
                        _src_ip_bytes[2],
                        _src_ip_bytes[3],
                        cnt.count,
                        threshold,
                        window_ns / 1_000_000_000u64
                    );
                }
                if cnt.count > threshold {
                    // block
                    let _trigger_count = cnt.count;
                    let expire = now + block_ns;
                    if unlikely(BLOCKED.insert(&source_addr, &expire, 0).is_err()) {
                        error!(
                            &ctx,
                            "failed to insert into BLOCKED for src_ip:{}.{}.{}.{}",
                            _src_ip_bytes[0],
                            _src_ip_bytes[1],
                            _src_ip_bytes[2],
                            _src_ip_bytes[3]
                        );
                    }
                    // reset counter in-place
                    cnt.last_ts = now;
                    cnt.count = 0;
                    error!(
                        &ctx,
                        "port {},ip {}.{}.{}.{} blocked: count={} threshold={} duration={}s",
                        dest_port,
                        _src_ip_bytes[0],
                        _src_ip_bytes[1],
                        _src_ip_bytes[2],
                        _src_ip_bytes[3],
                        _trigger_count,
                        threshold,
                        block_ns / 1_000_000_000u64
                    );
                    if rst_flag {
                        match send_rst(&ctx, ethhdr, ipv4hdr, tcphdr) {
                            Ok(_) => return Ok(xdp_action::XDP_TX),
                            Err(_) => return Ok(xdp_action::XDP_DROP),
                        }
                    } else {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
                // else: in-place updated, no insert needed
            }
        }
        None => {
            // insert new
            let nc = SynCounter {
                last_ts: now,
                count: 1,
                _pad: 0,
            };
            unsafe {
                let status = COUNTERS.insert(&source_addr, &nc, 0).is_err();
                if unlikely(status) {
                    error!(
                        &ctx,
                        "failed to insert new COUNTERS for src_ip:{}.{}.{}.{}",
                        _src_ip_bytes[0],
                        _src_ip_bytes[1],
                        _src_ip_bytes[2],
                        _src_ip_bytes[3]
                    );
                }
            }
        }
    }

    debug!(
        &ctx,
        "finish,src_ip:{}.{}.{}.{} port:{}",
        _src_ip_bytes[0],
        _src_ip_bytes[1],
        _src_ip_bytes[2],
        _src_ip_bytes[3],
        dest_port
    );
    Ok(xdp_action::XDP_PASS)
}
const ETH_LEN: usize = 14;
const IP_LEN: usize = 20;
const TCP_LEN: usize = 20;
const TOTAL_HDR_LEN: usize = ETH_LEN + IP_LEN + TCP_LEN;
// Build a minimal IPv4/TCP RST packet in-place and transmit using XDP_TX.
// Returns Ok(()) on success, Err(()) on failure.
#[inline(always)]
fn send_rst(
    ctx: &XdpContext,
    ethhdr: *const EthHdr,
    ipv4hdr: *const Ipv4Hdr,
    tcphdr: *const TcpHdr,
) -> Result<(), ()> {
    //return Err(());
    //bpf_xdp_adjust_tail,所以保存
    let (src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack_seq, ack_flag) = unsafe {
        (
            (*ethhdr).src_addr,
            (*ethhdr).dst_addr,
            (*ipv4hdr).src_addr,
            (*ipv4hdr).dst_addr,
            (*tcphdr).source,
            (*tcphdr).dest,
            u32::from_be_bytes((*tcphdr).seq),
            u32::from_be_bytes((*tcphdr).ack_seq),
            (*tcphdr).ack(),
        )
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    let old_len = data_end - data;
    let delta = (TOTAL_HDR_LEN as isize) - (old_len as isize);

    // 调用 helper 调整大小
    if delta != 0 {
        unsafe {
            if helpers::bpf_xdp_adjust_tail(ctx.ctx, delta as i32) < 0 {
                return Err(());
            }
        }
    }
    //bpf_xdp_adjust_tail,所以保存
    let data = ctx.data();
    let data_end = ctx.data_end();

    // 关键边界检查：告诉验证器我们不会越界
    if data + TOTAL_HDR_LEN > data_end {
        return Err(());
    }

    //直接修改原包,创建一个覆盖整个包头的 mut slice
    let pkt = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, TOTAL_HDR_LEN) };

    // --- 1. Ethernet Header (0..14) ---
    // 交换 MAC 地址
    pkt[0..6].copy_from_slice(&src_mac); // Dst = Old Src
    pkt[6..12].copy_from_slice(&dst_mac); // Src = Old Dst
    // EtherType IPv4 (0x0800)
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // --- 2. IPv4 Header (14..34) ---
    let ip_off = ETH_LEN;
    pkt[ip_off] = 0x45; // Ver=4, IHL=5
    pkt[ip_off + 1] = 0; // TOS
    // Total Len = 40 (0x0028) Big Endian
    pkt[ip_off + 2] = 0x00;
    pkt[ip_off + 3] = 0x28;
    // ID, Flags, FragOff 均设为 0
    pkt[ip_off + 4..ip_off + 8].fill(0);
    pkt[ip_off + 8] = 64; // TTL
    pkt[ip_off + 9] = 6; // Proto TCP
    pkt[ip_off + 10] = 0;
    pkt[ip_off + 11] = 0; // Checksum init

    // 交换 IP 地址
    let new_src = &dst_ip;
    let new_dst = &src_ip;
    pkt[ip_off + 12..ip_off + 16].copy_from_slice(new_src);
    pkt[ip_off + 16..ip_off + 20].copy_from_slice(new_dst);

    // 计算 IP Checksum
    let ip_csum = calc_csum(&pkt[ip_off..ip_off + IP_LEN]);
    pkt[ip_off + 10] = (ip_csum >> 8) as u8;
    pkt[ip_off + 11] = (ip_csum & 0xff) as u8;

    // --- 3. TCP Header (34..54) ---
    let tcp_off = ETH_LEN + IP_LEN;
    // 交换端口
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&dst_port);
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&src_port);

    // 计算 Seq 和 Ack
    // 如果收到的包有 ACK，我们用该 ACK 作为我们的 Seq
    // 如果收到的包是 SYN，我们 Seq=0, Ack=OldSeq+1
    // 这里采用通用 RST 响应逻辑：
    let new_seq = if ack_flag == 1 { ack_seq } else { 0 };
    let new_ack = if ack_flag == 1 {
        0
    } else {
        seq.wrapping_add(1)
    };

    pkt[tcp_off + 4..tcp_off + 8].copy_from_slice(&u32::to_be_bytes(new_seq));
    pkt[tcp_off + 8..tcp_off + 12].copy_from_slice(&u32::to_be_bytes(new_ack));

    // Data Offset (5 words) | Flags
    pkt[tcp_off + 12] = 0x50;
    // Flags: 如果原包是 SYN，我们回 RST|ACK (0x14)。如果是其他，回 RST (0x04) 也可以，视 RFC 而定。
    // 为了对抗 SYN Flood，通常回 RST|ACK 以确保能够拆除对端连接。
    pkt[tcp_off + 13] = if ack_flag == 0 { 0x14 } else { 0x04 };

    // Window, Csum, UrgPtr 全部清零
    pkt[tcp_off + 14..tcp_off + 20].fill(0);

    // --- 4. TCP Checksum 计算 ---
    // 伪首部 (Pseudo Header) 部分
    let mut sum = 0u32;
    sum += (u32::from_be_bytes(dst_ip) >> 16) + (u32::from_be_bytes(dst_ip) & 0xffff); // Src IP
    sum += (u32::from_be_bytes(src_ip) >> 16) + (u32::from_be_bytes(src_ip) & 0xffff); // Dst IP
    sum += 6 + 20; // Proto + TCP Len

    // TCP 首部部分 (利用 chunks_exact 展开循环，满足验证器)
    for chunk in pkt[tcp_off..].chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }

    // 折叠校验和
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let tcp_csum = !sum as u16;

    // 填入校验和
    pkt[tcp_off + 16] = (tcp_csum >> 8) as u8;
    pkt[tcp_off + 17] = (tcp_csum & 0xff) as u8;

    Ok(())
}
#[inline(always)]
fn calc_csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks_exact(2) {
        let word = (chunk[0] as u32) << 8 | (chunk[1] as u32);
        sum = sum.wrapping_add(word);
    }
    if let Some(&byte) = data.chunks_exact(2).remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
