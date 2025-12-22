#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::{mem, mem::size_of};

use aya_ebpf::{
    bindings::xdp_action,
    helpers,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SynCounter {
    last_ts: u64,
    count: u32,
    _pad: u32,
}

#[map(name = "PORTS")]
static mut PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(256, 0);

#[map(name = "COUNTERS")]
static mut COUNTERS: LruHashMap<u32, SynCounter> =
    LruHashMap::<u32, SynCounter>::with_max_entries(1024, 0);

#[map(name = "BLOCKED")]
static mut BLOCKED: LruHashMap<u32, u64> = LruHashMap::<u32, u64>::with_max_entries(1024, 0);

#[map(name = "CONFIG")]
static mut CONFIG: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(4, 0);

const KEY_WINDOW_NS: u32 = 0; // window seconds in ns stored as u64
const KEY_THRESHOLD: u32 = 1; // threshold stored as u64
const KEY_BLOCK_NS: u32 = 2; // block seconds in ns stored as u64

fn parse_ipv4(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}
#[inline(always)] // (1)
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
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_syn_block(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                if (*tcphdr).syn() != 1 {
                    debug!(&ctx, "not syn packet, xdp pass");
                    return Ok(xdp_action::XDP_PASS);
                }
            }
            u16::from_be_bytes(unsafe { (*tcphdr).dest })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    //我们只处理ssh，即tcp
    //过多的syn即视为攻击

    let src_ip_bytes = parse_ipv4(source_addr);
    info!(
        &ctx,
        "dest_port {}  src_port {} syn packet from src_ip:{}.{}.{}.{}",
        dest_port,
        source_port,
        src_ip_bytes[0],
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3]
    ); //u32

    // check whether this dst port is monitored
    let monitored = unsafe { PORTS.get(&dest_port) };

    if monitored.is_none() {
        debug!(&ctx, "no the monitored port, xdp pass");
        return Ok(xdp_action::XDP_PASS);
    }

    warn!(
        &ctx,
        "monitored port {} syn packet from src_ip:{}.{}.{}.{}",
        dest_port,
        src_ip_bytes[0],
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3]
    ); //u32
    // Get config values (if absent, use defaults)
    let now = unsafe { helpers::bpf_ktime_get_ns() } as u64;
    let window_ns = match unsafe { CONFIG.get(&KEY_WINDOW_NS) } {
        Some(v) => *v,
        None => 10u64 * 1_000_000_000u64,
    };
    let threshold = match unsafe { CONFIG.get(&KEY_THRESHOLD) } {
        Some(v) => *v as u32,
        None => 3u32,
    };
    let block_ns = match unsafe { CONFIG.get(&KEY_BLOCK_NS) } {
        Some(v) => *v,
        None => 60u64 * 1_000_000_000u64,
    };

    // If blocked and block not expired -> DROP
    if let Some(expire) = unsafe { BLOCKED.get(&source_addr) } {
        if *expire > now {
            warn!(
                &ctx,
                "port {},ip {}.{}.{}.{} still blocked,xdp drop",
                dest_port,
                src_ip_bytes[0],
                src_ip_bytes[1],
                src_ip_bytes[2],
                src_ip_bytes[3]
            );
            return Ok(xdp_action::XDP_DROP);
        } else {
            // remove expired entry
            unsafe {
                let _ = BLOCKED.remove(&source_addr);
            }
        }
    }

    // update counter
    if let Some(curr) = unsafe { COUNTERS.get(&source_addr) } {
        let mut cnt = *curr;
        // existing
        if now - cnt.last_ts <= window_ns {
            cnt.count = cnt.count.saturating_add(1);
        } else {
            cnt.count = 1;
            cnt.last_ts = now;
        }
        if cnt.count > threshold {
            // block
            let expire = now + block_ns;
            unsafe {
                if BLOCKED.insert(&source_addr, &expire, 0).is_err() {
                    warn!(
                        &ctx,
                        "failed to insert into BLOCKED for src_ip:{}.{}.{}.{}",
                        src_ip_bytes[0],
                        src_ip_bytes[1],
                        src_ip_bytes[2],
                        src_ip_bytes[3]
                    );
                }
            }
            // reset counter
            let reset = SynCounter {
                last_ts: now,
                count: 0,
                _pad: 0,
            };
            unsafe {
                if COUNTERS.insert(&source_addr, &reset, 0).is_err() {
                    warn!(
                        &ctx,
                        "failed to reset COUNTERS for src_ip:{}.{}.{}.{}",
                        src_ip_bytes[0],
                        src_ip_bytes[1],
                        src_ip_bytes[2],
                        src_ip_bytes[3]
                    );
                }
            }
            warn!(
                &ctx,
                "port {},ip {}.{}.{}.{} blocked,xdp drop",
                dest_port,
                src_ip_bytes[0],
                src_ip_bytes[1],
                src_ip_bytes[2],
                src_ip_bytes[3]
            );
            return Ok(xdp_action::XDP_DROP);
        } else {
            // update counter
            unsafe {
                if COUNTERS.insert(&source_addr, &cnt, 0).is_err() {
                    warn!(
                        &ctx,
                        "failed to update COUNTERS for src_ip:{}.{}.{}.{}",
                        src_ip_bytes[0],
                        src_ip_bytes[1],
                        src_ip_bytes[2],
                        src_ip_bytes[3]
                    );
                }
            }
        }
    } else {
        // insert new
        let nc = SynCounter {
            last_ts: now,
            count: 1,
            _pad: 0,
        };
        unsafe {
            if COUNTERS.insert(&source_addr, &nc, 0).is_err() {
                warn!(
                    &ctx,
                    "failed to insert new COUNTERS for src_ip:{}.{}.{}.{}",
                    src_ip_bytes[0],
                    src_ip_bytes[1],
                    src_ip_bytes[2],
                    src_ip_bytes[3]
                );
            }
        }
    }

    warn!(
        &ctx,
        "finish,src_ip:{}.{}.{}.{} port:{}",
        src_ip_bytes[0],
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3],
        dest_port
    );
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
