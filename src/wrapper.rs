use crate::models::{common, encoding};

use serde::{Deserialize, Serialize};

/// This wrapper exists because the Ord and Eq implementations on TIEID are probably wrong.
/// From the spec, Section 4.2.3.3
/// TIEs are uniquely identifed by `TIEID` schema element. `TIEID` space is a total order achieved
/// by comparing the elements in sequence defined in the element and comparing each value as an
/// unsigned integer of according length. They contain a `seq_nr` element to distinguish newer
/// versions of same TIE. TIEIDs also carry `origination_time` and `origination_lifetime`. Field
/// `origination_time` contains the absolute timestamp when the TIE was generated. Field
/// `origination_lifetime` carries lifetime when the TIE was generated. Those are normally
/// disregarded during comparison and carried purely for debugging/security purposes if present.
/// They may be used for comparison of last resort to differentiate otherwise equal ties and they
/// can be used on fabrics with synchronized clock to prevent lifetime modification attacks.
/// Remaining lifetime counts down to 0 from origination lifetime. TIEs with lifetimes differing by
/// less than `lifetime_diff2ignore` MUST be considered EQUAL (if all other fields are equal). This
/// constant MUST be larger than `purge_lifetime` to avoid retransmissions.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct TIEIDWrapper {
    /// direction of TIE
    pub direction: TieDirection,
    /// indicates originator of the TIE
    pub originator: SystemID,
    /// type of the tie
    pub tie_type: TIESubtype,
    /// number of the tie
    pub tie_nr: TieNumber,
}

impl From<encoding::TIEID> for TIEIDWrapper {
    fn from(value: encoding::TIEID) -> Self {
        TIEIDWrapper {
            direction: value.direction.try_into().unwrap(),
            originator: SystemID(value.originator as u64),
            tie_type: value.tietype.try_into().unwrap(),
            tie_nr: value.tie_nr.try_into().unwrap(),
        }
    }
}

impl From<TIEIDWrapper> for encoding::TIEID {
    fn from(value: TIEIDWrapper) -> Self {
        encoding::TIEID {
            direction: value.direction.into(),
            originator: value.originator.into(),
            tietype: value.tie_type.into(),
            tie_nr: value.tie_nr.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TieDirection {
    South,
    North,
}

impl TryFrom<common::TieDirectionType> for TieDirection {
    type Error = String;

    fn try_from(value: common::TieDirectionType) -> Result<Self, Self::Error> {
        match value {
            common::TieDirectionType::SOUTH => Ok(TieDirection::South),
            common::TieDirectionType::NORTH => Ok(TieDirection::North),
            _ => Err(format!(
                "Invalid TieDirection value. (Expected {} (north) or {} (south), got {})",
                common::TieDirectionType::NORTH.0,
                common::TieDirectionType::SOUTH.0,
                value.0
            )),
        }
    }
}

impl From<TieDirection> for common::TieDirectionType {
    fn from(value: TieDirection) -> Self {
        match value {
            TieDirection::South => common::TieDirectionType::SOUTH,
            TieDirection::North => common::TieDirectionType::NORTH,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TIESubtype {
    Node,
    Prefix,
    PositiveDisaggregationPrefix,
    NegativeDisaggregationPrefix,
    PGPrefix,
    KeyValue,
    ExternalPrefix,
    PositiveExternalDisaggregation,
}

impl TryFrom<common::TIETypeType> for TIESubtype {
    type Error = String;

    fn try_from(value: common::TIETypeType) -> Result<Self, Self::Error> {
        use common::TIETypeType;
        let value = match value {
            TIETypeType::NODE_T_I_E_TYPE => TIESubtype::Node,
            TIETypeType::PREFIX_T_I_E_TYPE => TIESubtype::Prefix,
            TIETypeType::POSITIVE_DISAGGREGATION_PREFIX_T_I_E_TYPE => {
                TIESubtype::PositiveDisaggregationPrefix
            }
            TIETypeType::NEGATIVE_DISAGGREGATION_PREFIX_T_I_E_TYPE => {
                TIESubtype::NegativeDisaggregationPrefix
            }
            TIETypeType::P_G_PREFIX_T_I_E_TYPE => TIESubtype::PGPrefix,
            TIETypeType::KEY_VALUE_T_I_E_TYPE => TIESubtype::KeyValue,
            TIETypeType::EXTERNAL_PREFIX_T_I_E_TYPE => TIESubtype::ExternalPrefix,
            TIETypeType::POSITIVE_EXTERNAL_DISAGGREGATION_PREFIX_T_I_E_TYPE => {
                TIESubtype::PositiveExternalDisaggregation
            }
            _ => {
                return Err(format!(
                    "Illegal TIETypeType value. (Expected a value between {} and {}, got {})",
                    TIETypeType::NODE_T_I_E_TYPE.0,
                    TIETypeType::POSITIVE_EXTERNAL_DISAGGREGATION_PREFIX_T_I_E_TYPE.0,
                    value.0
                ))
            }
        };
        Ok(value)
    }
}

impl From<TIESubtype> for common::TIETypeType {
    fn from(value: TIESubtype) -> Self {
        use common::TIETypeType;
        match value {
            TIESubtype::Node => TIETypeType::NODE_T_I_E_TYPE,
            TIESubtype::Prefix => TIETypeType::PREFIX_T_I_E_TYPE,
            TIESubtype::PositiveDisaggregationPrefix => {
                TIETypeType::POSITIVE_DISAGGREGATION_PREFIX_T_I_E_TYPE
            }
            TIESubtype::NegativeDisaggregationPrefix => {
                TIETypeType::NEGATIVE_DISAGGREGATION_PREFIX_T_I_E_TYPE
            }
            TIESubtype::PGPrefix => TIETypeType::P_G_PREFIX_T_I_E_TYPE,
            TIESubtype::KeyValue => TIETypeType::KEY_VALUE_T_I_E_TYPE,
            TIESubtype::ExternalPrefix => TIETypeType::EXTERNAL_PREFIX_T_I_E_TYPE,
            TIESubtype::PositiveExternalDisaggregation => {
                TIETypeType::POSITIVE_EXTERNAL_DISAGGREGATION_PREFIX_T_I_E_TYPE
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TieNumber {
    value: u32,
}
impl TryFrom<common::TIENrType> for TieNumber {
    type Error = String;

    fn try_from(value: common::TIENrType) -> Result<Self, Self::Error> {
        if value >= 0 {
            Ok(TieNumber {
                value: value as u32,
            })
        } else {
            Err(format!(
                "Illegal TIENrType value. (Expected positive value, got {})",
                value
            ))
        }
    }
}
impl From<TieNumber> for common::TIENrType {
    fn from(value: TieNumber) -> Self {
        value.value as common::TIENrType
    }
}

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
