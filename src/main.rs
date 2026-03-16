use anyhow::Context as _;
use aya::EbpfLoader;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{debug, warn};
use tokio::signal;

use std::path::Path;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "veth-test")]
    iface: String,
    #[clap(short, long)]
    obj: String,
    #[clap(long, default_value = "/sys/fs/bpf/zeek")]
    pin_path_prefix: String,
    #[clap(long, default_value_t = 65535)]
    flow_map_max_size: u32,
    #[clap(long, default_value_t = 65535)]
    ip_pair_map_max_size: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

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

    let Opt {
        iface,
        obj,
        pin_path_prefix,
        flow_map_max_size,
        ip_pair_map_max_size,
    } = opt;
    let pin_path = Path::new(&pin_path_prefix);
    std::fs::create_dir_all(pin_path)?;
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_path)
        .map_max_entries("filter_map", flow_map_max_size)
        .map_max_entries("ip_pair_map", ip_pair_map_max_size)
        .load_file(obj)?;

    let program: &mut Xdp = ebpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
