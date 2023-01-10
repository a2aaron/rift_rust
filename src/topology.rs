use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroUsize};

use serde::{Deserialize, Serialize};

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
    constant: GlobalConstants, // spec lies: this is optional
    #[serde(default)]
    authentication_keys: Vec<KeyDescription>, // spec lies: this is called authentication_keys, not keys
    shards: Vec<Shard>,
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
struct GlobalConstants {
    tx_src_address: Option<Ipv4Addr>,
    tx_v6_src_address: Option<Ipv6Addr>,
    rx_mcast_address: Option<Ipv4Addr>,
    lie_mcast_address: Option<Ipv4Addr>,
    flooding_reduction: Option<bool>,
    flooding_reduction_redundancy: Option<NonZeroUsize>,
    flooding_reduction_similarity: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyDescription {
    id: NonZeroU32, // Actually a u24
    algorithm: KeyAlgorithm,
    secret: String,
    #[serde(rename = "private-secret")]
    private_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum KeyAlgorithm {
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
struct Shard {
    id: u64,
    nodes: Vec<Node>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Node {
    name: String,
    #[serde(default = "default_false")]
    passive: bool,
    #[serde(default)]
    level: Level, // spec lies: this is optional and defaults to "undefined" if not provided
    #[serde(rename = "systemid")]
    system_id: SystemID,
    rx_lie_mcast_address: Option<Ipv4Addr>,
    rx_lie_v6_mcast_address: Option<Ipv6Addr>,
    rx_lie_port: Option<usize>, // spec lies: this is optional
    state_thrift_services_port: Option<usize>,
    config_thrift_services_port: Option<usize>,
    #[serde(default = "default_true")]
    generate_defaults: bool,
    active_key: Option<u32>, // Actually a u24
    #[serde(default)]
    tie_validation: Validation,
    interfaces: Vec<Interface>,
    #[serde(default)]
    v4prefixes: Vec<V4Prefix>,
    #[serde(default)]
    v6prefixes: Vec<V6Prefix>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Interface {
    name: String,
    bandwidth: Option<usize>,
    metric: Option<NonZeroUsize>,
    tx_lie_port: Option<usize>,
    rx_lie_port: Option<usize>,
    rx_tie_port: Option<usize>,
    #[serde(default = "default_false")]
    advertise_subnet: bool,
    active_key: Option<u8>,
    #[serde(default)]
    accept_keys: HashSet<u8>,
    #[serde(default)]
    link_validation: Validation,
}

// TODO: I don't like `NamedLevel` being distinct, but I can't figure out how to do this otherwise
// Maybe I should implement Serialize/Deserialize manually?
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Level {
    Number(usize),
    NamedLevel(NamedLevel),
}

impl Default for Level {
    fn default() -> Self {
        Level::NamedLevel(NamedLevel::Undefined)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum NamedLevel {
    Undefined,
    Leaf,
    LeafToLeaf,
    TopOfFabric,
    // spec lies: this is not listed in the spec but is used by two_by_two_by_two_ztp
    // i do not know what it means.
    Superspine,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemID(u64);

#[derive(Debug, Default, Serialize, Deserialize)]
enum Validation {
    #[default]
    None,
    Permissive,
    Loose,
    Strict,
}

#[derive(Debug, Serialize, Deserialize)]
struct V4Prefix {
    address: Ipv4Addr,
    mask: usize,
    metric: NonZeroUsize,
}

#[derive(Debug, Serialize, Deserialize)]
struct V6Prefix {
    address: Ipv6Addr,
    mask: usize,
    metric: NonZeroUsize,
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
