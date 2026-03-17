use aya::Pod;
use aya::maps::{HashMap, Map, MapData};

use std::path::Path;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct canonical_tuple {
    pub ip1: [u8; 16],
    pub ip2: [u8; 16],
    pub port1: u16,
    pub port2: u16,
    pub protocol: u16,
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
    pub _padding: u16,
}

unsafe impl Pod for canonical_tuple {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ip_pair {
    pub ip1: [u8; 16],
    pub ip2: [u8; 16],
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
}

unsafe impl Pod for ip_pair {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct shunt_val {
    pub lock_pad: u32,
    pub packets_from_1: u64,
    pub packets_from_2: u64,
    pub bytes_from_1: u64,
    pub bytes_from_2: u64,
    pub timestamp: u64,
}

unsafe impl Pod for shunt_val {}

pub const FILTER_MAP_NAME: &str = "filter_map";
pub const IP_PAIR_MAP_NAME: &str = "ip_pair_map";

fn get_shunt_map<KeyTy>(
    pin_path: &Path,
    map_name: &str,
) -> anyhow::Result<HashMap<MapData, KeyTy, shunt_val>>
where
    KeyTy: Pod,
{
    let map_data = MapData::from_pin(pin_path.join(map_name))
        .map_err(|e| anyhow::anyhow!("Failed to load map from pin: {}", e))?;

    let raw_map = Map::HashMap(map_data);
    HashMap::try_from(raw_map)
        .map_err(|_| anyhow::anyhow!("Map is not a HashMap or types don't match"))
}

pub fn get_filter_map(
    pin_path: &Path,
) -> anyhow::Result<HashMap<MapData, canonical_tuple, shunt_val>> {
    get_shunt_map(pin_path, FILTER_MAP_NAME)
}

pub fn get_ip_pair_map(pin_path: &Path) -> anyhow::Result<HashMap<MapData, ip_pair, shunt_val>> {
    get_shunt_map(pin_path, IP_PAIR_MAP_NAME)
}
