use anyhow::anyhow;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]

use tokio::signal;

#[allow(unused)]
use log::{debug, error, info, warn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'i', long = "iface", default_value = "eth0")]
    iface: String,

    /// XDP attach mode: skb, drv, hw (default: skb)
    #[clap(short = 'm', long = "mode", value_parser = ["skb", "drv", "hw"], default_value = "skb")]
    mode: String,

    /// Comma-separated list of ports, e.g. 22,80,6666
    #[clap(short = 'p', long = "ports", value_delimiter = ',')]
    ports: Vec<u16>,

    /// Path to ports file (overrides PORTS_FILE env var)
    #[clap(short = 'f', long = "ports-file")]
    ports_file: Option<String>,

    /// Window seconds for counting (overrides WINDOW_SECS)
    #[clap(short = 'w', long = "window-secs")]
    window_secs: Option<u64>,

    /// Threshold count to trigger block (overrides THRESHOLD)
    #[clap(short = 't', long = "threshold")]
    threshold: Option<u64>,

    /// Block duration in seconds (overrides BLOCK_SECS)
    #[clap(short = 'b', long = "block-secs")]
    block_secs: Option<u64>,

    /// Send TCP RST when dropping (useful to terminate attackers quickly)
    #[clap(long = "rst", action)]
    rst: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt {
        iface,
        mode,
        ports,
        ports_file,
        window_secs: cli_window_secs,
        threshold: cli_threshold,
        block_secs: cli_block_secs,
        rst: cli_rst,
    } = opt;

    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "off")).init();
    let pid = std::process::id();
    info!(
        "starting syn_block eBPF program loader; iface={} pid={} version={}",
        iface,
        pid,
        env!("CARGO_PKG_VERSION")
    );

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!(
            "remove limit on locked memory failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/syn_block"
    )))?;
    info!("rust eBPF program loaded");
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            error!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // read ports file and populate PORTS map and CONFIG
    let ports_file = match ports_file {
        Some(p) => p,
        None => std::env::var("PORTS_FILE").unwrap_or_else(|_| "./ports".to_string()),
    };
    let window_secs: u64 = cli_window_secs
        .or_else(|| {
            std::env::var("WINDOW_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(10);
    let threshold: u64 = cli_threshold
        .or_else(|| std::env::var("THRESHOLD").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(3);
    let block_secs: u64 = cli_block_secs
        .or_else(|| {
            std::env::var("BLOCK_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(60);

    // populate PORTS map (from CLI --ports/-p or ports file)
    let map_ref = ebpf
        .map_mut("PORTS")
        .ok_or_else(|| anyhow!("map PORTS not found"))?;
    let mut ports_map = aya::maps::HashMap::<_, u16, u8>::try_from(map_ref)?;
    let mut ports_loaded = 0u32;
    if !ports.is_empty() {
        for p in &ports {
            let key = *p as u16;
            let val: u8 = 1;
            if ports_map.insert(&key, &val, 0).is_ok() {
                ports_loaded += 1;
            }
        }
    } else if let Ok(contents) = std::fs::read_to_string(&ports_file) {
        for line in contents.lines() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            if let Ok(p) = s.parse::<u16>() {
                let key = p as u16;
                let val: u8 = 1;
                if ports_map.insert(&key, &val, 0).is_ok() {
                    ports_loaded += 1;
                }
            }
        }
    }

    if !ports.is_empty() {
        info!("monitoring ports (CLI): {:?}", ports);
    } else {
        info!("monitoring ports (file): {}", ports_file);
    }
    if ports_loaded == 0 {
        error!(
            "no monitored ports loaded; no port is being monitored. Use --ports or set PORTS_FILE."
        );
    }

    // set config values (Array map: indexes 0=window ns, 1=threshold, 2=block ns)
    let cfg_ref = ebpf
        .map_mut("CONFIG")
        .ok_or_else(|| anyhow!("map CONFIG not found"))?;
    let mut cfg = aya::maps::Array::<_, u64>::try_from(cfg_ref)?;
    let _ = cfg.set(0u32, &(window_secs * 1_000_000_000u64), 0);
    let _ = cfg.set(1u32, &threshold, 0);
    let _ = cfg.set(2u32, &(block_secs * 1_000_000_000u64), 0);
    // index 3: rst flag (0 = disabled, 1 = enabled)
    let rst_val: u64 = if cli_rst { 1 } else { 0 };
    let _ = cfg.set(3u32, &rst_val, 0);
    info!(
        "CONFIG set: window_secs={}s threshold={} block_secs={}s rst={}",
        window_secs, threshold, block_secs, rst_val
    );

    let program: &mut Xdp = ebpf.program_mut("syn_block").unwrap().try_into()?;
    program.load()?;
    // Attach using user-selected mode
    let flags = match mode.as_str() {
        "skb" => XdpFlags::SKB_MODE,
        "drv" => XdpFlags::DRV_MODE,
        "hw" => XdpFlags::HW_MODE,
        _ => XdpFlags::SKB_MODE,
    };
    if let Err(e) = program.attach(&iface, flags) {
        return Err(anyhow!(
            "failed to attach the XDP program with mode '{}' on iface {}: {e}",
            mode,
            iface
        ));
    } else {
        info!(
            "attached the XDP program using mode '{}' on iface {}",
            mode, iface
        );
    }

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
