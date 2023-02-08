use crate::models::{common, encoding};

use serde::{Deserialize, Serialize};

/// A per-node, network-unique ID. From the spec:
/// Each RIFT node identifies itself by a valid, network wide unique number when trying to build
/// adjacencies or describing its topology. RIFT System IDs can be auto-derived or configured.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemID(u64);

impl SystemID {
    /// Get the inner type as a `common::SystemIDType`
    pub fn get(&self) -> common::SystemIDType {
        self.0 as common::SystemIDType
    }
}

impl TryFrom<common::SystemIDType> for SystemID {
    type Error = String;

    fn try_from(value: common::SystemIDType) -> Result<Self, Self::Error> {
        match value {
            common::ILLEGAL_SYSTEM_I_D => Err(format!(
                "Illegal system ID (equal to {}, the illegal system ID)",
                common::ILLEGAL_SYSTEM_I_D
            )),
            x if x < 0 => Err(format!(
                "Illegal system ID (expected positive value, got {})",
                value
            )),
            _ => Ok(SystemID(value as u64)),
        }
    }
}

impl From<SystemID> for common::SystemIDType {
    fn from(value: SystemID) -> Self {
        value.get()
    }
}
