mod maps;

use anyhow::Context as _;
use aya::EbpfLoader;
use aya::programs::{Xdp, XdpFlags, links::FdLink};
use clap::{Parser, Subcommand, ValueEnum};
use log::debug;

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

#[derive(Debug, Parser)]
struct Opt {
    #[command(subcommand)]
    command: Commands,
    #[clap(long, default_value = "/sys/fs/bpf/zeek")]
    pin_path_prefix: String,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum MapTy {
    #[default]
    FlowMap,
    IpPairMap,
}

impl fmt::Display for MapTy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapTy::FlowMap => write!(f, "flow-map"),
            MapTy::IpPairMap => write!(f, "ip-pair-map"),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum XdpMode {
    Native,
    Skb,
    Hw,
    #[default]
    Unspecified,
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdpMode::Native => write!(f, "native"),
            XdpMode::Skb => write!(f, "skb"),
            XdpMode::Hw => write!(f, "hw"),
            XdpMode::Unspecified => write!(f, "unspecified"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    Load {
        #[clap(short, long)]
        obj: String,
        #[clap(short, long, default_value = "veth-test")]
        iface: String,
        #[clap(short, long, default_value_t)]
        mode: XdpMode,
        #[clap(long, default_value_t = 65535)]
        flow_map_max_size: u32,
        #[clap(long, default_value_t = 65535)]
        ip_pair_map_max_size: u32,
    },
    Count {
        #[arg(long, value_enum, default_value_t)]
        map: MapTy,
    },
    Dump {
        #[arg(long, value_enum, default_value_t)]
        map: MapTy,
        #[arg(short, long)]
        json: bool,
    },
}

fn load_command(
    obj: &str,
    pin_path: &Path,
    iface: &str,
    mode: XdpMode,
    flow_map_max_size: u32,
    ip_pair_map_max_size: u32,
) -> anyhow::Result<()> {
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_path)
        .map_max_entries("filter_map", flow_map_max_size)
        .map_max_entries("ip_pair_map", ip_pair_map_max_size)
        .load_file(obj)?;

    let program: &mut Xdp = ebpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;
    let mut flags = XdpFlags::default();
    match mode {
        XdpMode::Native => flags.insert(XdpFlags::DRV_MODE),
        XdpMode::Skb => flags.insert(XdpFlags::SKB_MODE),
        XdpMode::Hw => flags.insert(XdpFlags::HW_MODE),
        XdpMode::Unspecified => (),
    }
    let link_id = program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Pin the link so that the program stays alive
    let link = program.take_link(link_id)?;
    let fd_link = FdLink::try_from(link).context("Hello")?;
    fd_link.pin(pin_path.join(iface))?;

    Ok(())
}

fn dump_command_json(pin_path: &Path, map: MapTy) -> anyhow::Result<()> {
    let mut out = HashMap::new();

    match map {
        MapTy::FlowMap => {
            for ele in maps::get_filter_map(pin_path)?.iter() {
                let (key, val) = ele?;
                out.insert(format!("{key}"), val);
            }
        }
        MapTy::IpPairMap => {
            for ele in maps::get_ip_pair_map(pin_path)?.iter() {
                let (key, val) = ele?;
                out.insert(format!("{key}"), val);
            }
        }
    }

    let json_output = serde_json::to_string_pretty(&out)?;
    println!("{json_output}");

    Ok(())
}

fn dump_command_txt(pin_path: &Path, map: MapTy) -> anyhow::Result<()> {
    println!("Dumping {}:", map);
    match map {
        MapTy::FlowMap => {
            for ele in maps::get_filter_map(pin_path)?.iter() {
                let (key, val) = ele?;
                println!("Key: {key}");
                println!("Val: {val}");
                println!();
            }
        }
        MapTy::IpPairMap => {
            for ele in maps::get_ip_pair_map(pin_path)?.iter() {
                let (key, val) = ele?;
                println!("Key: {key}");
                println!("Val: {val}");
                println!();
            }
        }
    }
    Ok(())
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
        command,
        pin_path_prefix,
    } = opt;
    let pin_path = Path::new(&pin_path_prefix);

    match command {
        Commands::Load {
            obj,
            iface,
            mode,
            flow_map_max_size,
            ip_pair_map_max_size,
        } => {
            // May need to create the directory
            std::fs::create_dir_all(pin_path)?;

            load_command(
                &obj,
                pin_path,
                &iface,
                mode,
                flow_map_max_size,
                ip_pair_map_max_size,
            )?;
        }
        // Just counts the entries in the map for debugging
        Commands::Count { map } => {
            let count = match map {
                MapTy::FlowMap => maps::get_filter_map(pin_path)?.iter().count(),
                MapTy::IpPairMap => maps::get_ip_pair_map(pin_path)?.iter().count(),
            };

            println!("Found {} entries in map.", count)
        }
        // Dumps the map
        Commands::Dump { map, json } => {
            if json {
                dump_command_json(pin_path, map)?;
            } else {
                dump_command_txt(pin_path, map)?;
            }
        }
    }

    Ok(())
}
