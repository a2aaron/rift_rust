use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroUsize};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::lie_exchange;
use crate::models::common::{
    self, DEFAULT_LIE_UDP_PORT, DEFAULT_TIE_UDP_FLOOD_PORT, LEAF_LEVEL, TOP_OF_FABRIC_LEVEL,
};
use crate::packet::SecretKeyStore;

// 224.0.0.120
const DEFAULT_LIE_IPV4_MCAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 120);
// FF02::A1F7
#[allow(dead_code)]
const DEFAULT_LIE_IPV6_MCAST_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xA1F7);

/// A topology description which defines some aspects of the RIFT network, including:
/// - What nodes exist
/// - What physical links exist between nodes
/// - What addresses and ports nodes should communicate on
/// - What keys and secrets exist
/// - Certain aspects of the node, such as it's level, passive/non-passive status, system ID, etc
/// See [here](https://github.com/brunorijsman/rift-python/blob/master/topology/yaml_topology_schema.md) for the schema
/// (alternatively, see the same file in `topology/yaml_topology_schema.md)
#[derive(Debug, Serialize, Deserialize)]
pub struct TopologyDescription {
    #[serde(rename = "const", default)]
    pub constant: GlobalConstants, // spec lies: this is optional
    #[serde(default)]
    authentication_keys: Vec<Key>, // spec lies: this is called authentication_keys, not keys
    shards: Vec<Shard>,
}

impl TopologyDescription {
    /// Finalize the topology description. Specifically: this will set it up so that each Link knows
    /// the send and recv addresses for itself.
    pub fn finalize(&mut self) {
        let mut map = HashMap::new();
        for node in &self.get_nodes() {
            let addrs = node.get_addrs();
            for addr in addrs {
                let result = map.insert(addr.port(), addr);
                if let Some(old_addr) = result {
                    tracing::warn!(
                        port =% addr.port(),
                        old_addr =% old_addr.ip(),
                        new_addr =% addr.ip(),
                        "overwriting IP address associated with port",
                    )
                }
            }
        }
        for shard in &mut self.shards {
            for node in &mut shard.nodes {
                for interface in &mut node.interfaces {
                    let lie_rx_port = interface.rx_lie_port.unwrap_or(DEFAULT_LIE_UDP_PORT as u16);
                    let lie_tx_port = interface.tx_lie_port.unwrap_or(DEFAULT_LIE_UDP_PORT as u16);
                    let tie_rx_port = interface
                        .rx_tie_port
                        .unwrap_or(DEFAULT_TIE_UDP_FLOOD_PORT as u16);

                    // TODO: should this be rx_lie_port or some other value?
                    let tie_tx_port = interface
                        .rx_lie_port
                        .unwrap_or(DEFAULT_TIE_UDP_FLOOD_PORT as u16);

                    interface.lie_rx_addr = map.get(&lie_rx_port).copied();
                    interface.lie_tx_addr = map.get(&lie_tx_port).copied();
                    interface.tie_rx_addr = map.get(&tie_rx_port).copied();
                    interface.tie_tx_addr = map.get(&tie_tx_port).copied();

                    if interface.lie_rx_addr.is_none() {
                        tracing::error!(
                            node = node.name,
                            interface = interface.name,
                            port = lie_rx_port,
                            "missing address for lie_rx_addr (no corresponding IP address exists for port)"
                        )
                    }
                    if interface.lie_tx_addr.is_none() {
                        tracing::error!(
                            node = node.name,
                            interface = interface.name,
                            port = lie_tx_port,
                            "missing address for lie_tx_addr (no corresponding IP address exists for port)"
                        )
                    }
                }
            }
        }
    }

    /// Get all the nodes as one big vector instead of across shards.
    pub fn get_nodes(&self) -> Vec<&NodeDescription> {
        self.shards.iter().flat_map(|shard| &shard.nodes).collect()
    }

    /// Get all the keys.
    pub fn get_keys(&self) -> SecretKeyStore {
        let keys: HashMap<NonZeroU32, Key> = self
            .authentication_keys
            .iter()
            .map(|key| (key.id, key.clone()))
            .collect();
        SecretKeyStore::new(keys)
    }
}

/// The "const" field in the config isn't described in yaml_topology_schema.md for some reason.
/// However, looking at `config.py` from `rift-python`, it has this schema:
///```python
/// 'const': {
///     'type': 'dict',
///     'nullable': True,
///     'schema': {
///         'tx_src_address': {'type': 'ipv4address'},
///         'tx_v6_src_address': {'type': 'ipv6address'},
///         'rx_mcast_address': {'type': 'ipv4address'},
///         'lie_mcast_address': {'type': 'ipv4address'},
///         'flooding_reduction': {'type': 'boolean'},
///         'flooding_reduction_redundancy': {'type': 'integer', 'min': 1},
///         'flooding_reduction_similarity': {'type': 'integer', 'min': 0}
///     },
/// },
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlobalConstants {
    pub tx_src_address: Option<Ipv4Addr>,
    pub tx_v6_src_address: Option<Ipv6Addr>,
    pub rx_mcast_address: Option<Ipv4Addr>,
    pub lie_mcast_address: Option<Ipv4Addr>,
    pub flooding_reduction: Option<bool>,
    pub flooding_reduction_redundancy: Option<NonZeroUsize>,
    pub flooding_reduction_similarity: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Key {
    pub id: NonZeroU32, // Actually a u24
    pub algorithm: KeyAlgorithm,
    secret: String,
    #[serde(rename = "private-secret")]
    private_secret: Option<String>,
}

impl Key {
    /// Returns the fingerprint of the given payloads. The fingerprint is computed as the following:
    /// HASH(secret + payloads[0] + payloads[1] + ... + payloads[n])
    /// Where "+" is the concatenation operation.
    /// If the key is not in the keystore, a panic occurs
    pub fn compute_fingerprint(&self, payloads: &[&[u8]]) -> Vec<u8> {
        match self.algorithm {
            KeyAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::default();
                hasher.update(self.secret.as_bytes());
                for payload in payloads {
                    hasher.update(payload);
                }
                hasher.finalize().to_vec()
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum KeyAlgorithm {
    #[serde(rename = "hmac-sha-1")]
    HmacSha1,
    #[serde(rename = "hmac-sha-224")]
    HmacSha224,
    #[serde(rename = "hmac-sha-256")]
    HmacSha256,
    #[serde(rename = "hmac-sha-384")]
    HmacSha384,
    #[serde(rename = "hmac-sha-512")]
    HmacSha512,
    #[serde(rename = "sha-1")]
    Sha1,
    #[serde(rename = "sha-224")]
    Sha224,
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    Sha512,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Shard {
    pub id: u64,
    pub nodes: Vec<NodeDescription>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeDescription {
    pub name: String,
    #[serde(default = "default_false")]
    pub passive: bool,
    #[serde(default)]
    pub level: Level, // spec lies: this is optional and defaults to "undefined" if not provided
    #[serde(rename = "systemid")]
    pub system_id: SystemID,
    pub rx_lie_mcast_address: Option<Ipv4Addr>,
    pub rx_lie_v6_mcast_address: Option<Ipv6Addr>,
    pub rx_lie_port: Option<u16>, // spec lies: this is optional
    pub state_thrift_services_port: Option<u16>,
    pub config_thrift_services_port: Option<u16>,
    #[serde(default = "default_true")]
    pub generate_defaults: bool,
    pub active_key: Option<u32>, // Actually a u24
    #[serde(default)]
    pub tie_validation: Validation,
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub v4prefixes: Vec<V4Prefix>,
    #[serde(default)]
    pub v6prefixes: Vec<V6Prefix>,
}

impl NodeDescription {
    fn get_addrs(&self) -> Vec<SocketAddr> {
        let mut link_addrs = vec![];
        for interface in &self.interfaces {
            if let Some(rx_lie_port) = interface.rx_lie_port.or(self.rx_lie_port) {
                let v4_addr = self.rx_lie_mcast_address.map(IpAddr::V4);
                let v6_addr = self.rx_lie_v6_mcast_address.map(IpAddr::V6);
                let addr: IpAddr = v4_addr
                    .or(v6_addr)
                    .unwrap_or(DEFAULT_LIE_IPV4_MCAST_ADDRESS.into());

                let lie_rx_addr = SocketAddr::from((addr, rx_lie_port));
                link_addrs.push(lie_rx_addr);
            }

            if let Some(rx_tie_port) = interface.rx_tie_port {
                let v4_addr = self.rx_lie_mcast_address.map(IpAddr::V4);
                let v6_addr = self.rx_lie_v6_mcast_address.map(IpAddr::V6);
                let addr: IpAddr = v4_addr
                    .or(v6_addr)
                    .unwrap_or(DEFAULT_LIE_IPV4_MCAST_ADDRESS.into());
                let tie_rx_addr = SocketAddr::from((addr, rx_tie_port));
                link_addrs.push(tie_rx_addr);
            }
        }

        link_addrs
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub bandwidth: Option<usize>,
    pub metric: Option<NonZeroUsize>,
    tx_lie_port: Option<u16>,
    rx_lie_port: Option<u16>,
    rx_tie_port: Option<u16>,
    #[serde(default = "default_false")]
    pub advertise_subnet: bool,
    pub active_key: Option<u8>,
    #[serde(default)]
    pub accept_keys: HashSet<u8>,
    #[serde(default)]
    pub link_validation: Validation,
    #[serde(skip)]
    lie_tx_addr: Option<SocketAddr>,
    #[serde(skip)]
    lie_rx_addr: Option<SocketAddr>,
    #[serde(skip)]
    tie_tx_addr: Option<SocketAddr>,
    #[serde(skip)]
    tie_rx_addr: Option<SocketAddr>,
}

impl Interface {
    pub fn lie_tx_addr(&self) -> SocketAddr {
        self.lie_tx_addr.unwrap()
    }
    pub fn lie_rx_addr(&self) -> SocketAddr {
        self.lie_rx_addr.unwrap()
    }
    pub fn tie_tx_addr(&self) -> SocketAddr {
        self.tie_tx_addr.unwrap()
    }
    pub fn tie_rx_addr(&self) -> SocketAddr {
        self.tie_rx_addr.unwrap()
    }
}

/// The level a node has if it is configured to have one. This can be a number or a named level,
/// of which there are four special names: `undefined`, `leaf`, `leaf-to-leaf`, and `top-of-fabric`
/// Note that numerically, a level of `leaf` or `leaf-to-leaf` is equal to [common::LEAF_LEVEL] and
/// a level of `top-of-fabric` is equal to [common::TOP_OF_FABRIC_LEVEL]. If not provided in the
/// topology description, then the level for a node defaults to undefined.
// TODO: I don't like `NamedLevel` being distinct, but I can't figure out how to do this otherwise
// Maybe I should implement Serialize/Deserialize manually?
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Level {
    Number(usize),
    NamedLevel(NamedLevel),
}

impl From<Level> for lie_exchange::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::Number(number) => lie_exchange::Level::Value(number as u8),
            Level::NamedLevel(level) => match level {
                NamedLevel::Undefined => lie_exchange::Level::Undefined,
                NamedLevel::Leaf => lie_exchange::Level::Value(LEAF_LEVEL as u8),
                NamedLevel::LeafToLeaf => lie_exchange::Level::Value(LEAF_LEVEL as u8),
                NamedLevel::TopOfFabric => lie_exchange::Level::Value(TOP_OF_FABRIC_LEVEL as u8),
            },
        }
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::NamedLevel(NamedLevel::Undefined)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NamedLevel {
    Undefined,
    Leaf,
    LeafToLeaf,
    TopOfFabric,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct SystemID(u64);

impl SystemID {
    pub fn get(&self) -> common::SystemIDType {
        self.0 as common::SystemIDType
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub enum Validation {
    #[default]
    None,
    Permissive,
    Loose,
    Strict,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct V4Prefix {
    pub address: Ipv4Addr,
    pub mask: usize,
    pub metric: NonZeroUsize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct V6Prefix {
    pub address: Ipv6Addr,
    pub mask: usize,
    pub metric: NonZeroUsize,
}

// Serde calls a function when passing a default. These functions are just for convience since some
// of the fields need to default to true.

const fn default_false() -> bool {
    false
}
const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod test {
    use crate::topology::NamedLevel;

    use super::Level;

    #[test]
    fn test_serialize_level() {
        assert_eq!("413\n", serde_yaml::to_string(&Level::Number(413)).unwrap());
        assert_eq!(
            "leaf\n",
            serde_yaml::to_string(&Level::NamedLevel(NamedLevel::Leaf)).unwrap()
        );
        assert_eq!(
            "leaf-to-leaf\n",
            serde_yaml::to_string(&Level::NamedLevel(NamedLevel::LeafToLeaf)).unwrap()
        );
        assert_eq!(
            "top-of-fabric\n",
            serde_yaml::to_string(&Level::NamedLevel(NamedLevel::TopOfFabric)).unwrap()
        );
        assert_eq!(
            "undefined\n",
            serde_yaml::to_string(&Level::NamedLevel(NamedLevel::Undefined)).unwrap()
        );
    }
}
