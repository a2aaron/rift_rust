use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroUsize};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::lie_exchange;
use crate::models::common::{self, LEAF_LEVEL, TOP_OF_FABRIC_LEVEL};
use crate::packet::SecretKeyStore;

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
    pub fn get_nodes(&self) -> Vec<&NodeDescription> {
        self.shards.iter().flat_map(|shard| &shard.nodes).collect()
    }

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub bandwidth: Option<usize>,
    pub metric: Option<NonZeroUsize>,
    pub tx_lie_port: Option<u16>,
    pub rx_lie_port: Option<u16>,
    pub rx_tie_port: Option<u16>,
    #[serde(default = "default_false")]
    pub advertise_subnet: bool,
    pub active_key: Option<u8>,
    #[serde(default)]
    pub accept_keys: HashSet<u8>,
    #[serde(default)]
    pub link_validation: Validation,
}

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
