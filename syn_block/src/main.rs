use anyhow::anyhow;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short = 'i', long = "iface", default_value = "eth0")]
    iface: String,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt {
        iface,
        ports,
        ports_file,
        window_secs: cli_window_secs,
        threshold: cli_threshold,
        block_secs: cli_block_secs,
    } = opt;

    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "warn")).init();
    warn!("starting syn_block eBPF program loader");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/syn_block"
    )))?;
    warn!("rust eBPF program loaded");
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
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
    if !ports.is_empty() {
        for p in &ports {
            let key = *p as u16;
            let val: u8 = 1;
            let _ = ports_map.insert(&key, &val, 0);
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
                let _ = ports_map.insert(&key, &val, 0);
            }
        }
    }

    // set config values
    let cfg_ref = ebpf
        .map_mut("CONFIG")
        .ok_or_else(|| anyhow!("map CONFIG not found"))?;
    let mut cfg = aya::maps::HashMap::<_, u32, u64>::try_from(cfg_ref)?;
    let _ = cfg.insert(&0u32, &(window_secs * 1_000_000_000u64), 0);
    let _ = cfg.insert(&1u32, &threshold, 0);
    let _ = cfg.insert(&2u32, &(block_secs * 1_000_000_000u64), 0);

    let program: &mut Xdp = ebpf.program_mut("syn_block").unwrap().try_into()?;
    program.load()?;
    // Try default XDP mode first, fall back to SKB mode if it fails
    if let Err(e) = program.attach(&iface, XdpFlags::default()) {
        warn!("failed to attach the XDP program with default flags: {e}. Trying SKB_MODE...");
        if let Err(e2) = program.attach(&iface, XdpFlags::SKB_MODE) {
            return Err(anyhow!(
                "failed to attach the XDP program with default flags ({e}) and SKB_MODE ({e2})"
            ));
        } else {
            warn!("attached the XDP program using SKB_MODE");
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
