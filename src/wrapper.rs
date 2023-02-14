use std::{
    cmp::Ordering,
    collections::BTreeSet,
    time::{Duration, SystemTime},
};

use crate::models::{common, encoding};

use serde::{Deserialize, Serialize};

pub type LifetimeInSecs = u32;
pub type SequenceNumber = u32;

pub const TOP_OF_FABRIC_LEVEL: u8 = common::TOP_OF_FABRIC_LEVEL as u8;

/// TIE packet
#[derive(Clone, Debug)]
pub struct TIEPacket {
    pub header: TIEHeader,
    // TODO: Wrap TIEElement?
    pub element: encoding::TIEElement,
}

impl From<encoding::TIEPacket> for TIEPacket {
    fn from(value: encoding::TIEPacket) -> Self {
        TIEPacket {
            header: value.header.into(),
            element: value.element,
        }
    }
}

/// TIRE packet
#[derive(Clone, Debug)]
pub struct TIREPacket {
    pub headers: BTreeSet<TIEHeaderWithLifetime>,
}

impl From<encoding::TIREPacket> for TIREPacket {
    fn from(value: encoding::TIREPacket) -> Self {
        TIREPacket {
            headers: value.headers.iter().map(|x| x.clone().into()).collect(),
        }
    }
}

/// TIDE with *sorted* TIE headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TIDEPacket {
    /// First TIE header in the tide packet.
    /// If the value is None, then `start_range` is unboundedly small
    pub start_range: Option<TIEID>,
    /// Last TIE header in the tide packet.
    /// If the value is None, then `end_range` is unboundedly large
    pub end_range: Option<TIEID>,
    /// _Sorted_ list of headers.
    pub headers: Vec<TIEHeaderWithLifetime>,
}

const MIN_TIE_ID: encoding::TIEID = encoding::TIEID {
    direction: common::TieDirectionType::SOUTH,
    originator: 0,
    tietype: common::TIETypeType::T_I_E_TYPE_MIN_VALUE,
    tie_nr: 0,
};

const MAX_TIE_ID: encoding::TIEID = encoding::TIEID {
    direction: common::TieDirectionType::NORTH,
    originator: u64::MAX as common::SystemIDType,
    tietype: common::TIETypeType::T_I_E_TYPE_MAX_VALUE,
    tie_nr: u32::MAX as common::TIENrType,
};

impl From<encoding::TIDEPacket> for TIDEPacket {
    fn from(value: encoding::TIDEPacket) -> Self {
        let start_range = if value.start_range == MIN_TIE_ID {
            None
        } else {
            Some(value.start_range.into())
        };

        let end_range = if value.end_range == MAX_TIE_ID {
            None
        } else {
            Some(value.end_range.into())
        };

        TIDEPacket {
            start_range,
            end_range,
            headers: value.headers.iter().map(|x| x.clone().into()).collect(),
        }
    }
}

/// Header of a TIE as described in TIRE/TIDE.
/// TODO: Is the default Ord implementation fine for this?
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TIEHeaderWithLifetime {
    pub header: TIEHeader,
    /// Remaining lifetime.
    pub remaining_lifetime: LifetimeInSecs,
}

impl TIEHeaderWithLifetime {
    pub fn new(header: TIEHeader) -> TIEHeaderWithLifetime {
        TIEHeaderWithLifetime {
            header,
            remaining_lifetime: common::DEFAULT_LIFETIME as LifetimeInSecs,
        }
    }
}

impl From<encoding::TIEHeaderWithLifeTime> for TIEHeaderWithLifetime {
    fn from(value: encoding::TIEHeaderWithLifeTime) -> Self {
        TIEHeaderWithLifetime {
            header: value.header.into(),
            remaining_lifetime: value.remaining_lifetime as LifetimeInSecs,
        }
    }
}

impl From<TIEHeaderWithLifetime> for encoding::TIEHeaderWithLifeTime {
    fn from(value: TIEHeaderWithLifetime) -> Self {
        encoding::TIEHeaderWithLifeTime {
            header: value.header.into(),
            remaining_lifetime: value.remaining_lifetime as common::LifeTimeInSecType,
        }
    }
}

/// Header of a TIE.
/// NOTE: I am unsure if I implemented Ord correctly. From the spec:
/// TIEIDs [note: i think should read "TIEHeaders"] also carry `origination_time` and `origination_lifetime`. Field `origination_time`
/// contains the absolute timestamp when the TIE was generated. Field `origination_lifetime`
/// carries lifetime when the TIE was generated. Those are normally disregarded during comparison
/// and carried purely for debugging/security purposes if present. They may be used for comparison
/// of last resort to differentiate otherwise equal ties and they can be used on fabrics with
/// synchronized clock to prevent lifetime modification attacks.
/// Remaining lifetime counts down to 0 from origination lifetime. TIEs with lifetimes differing by
/// less than `lifetime_diff2ignore` MUST be considered EQUAL (if all other fields are equal). This
/// constant MUST be larger than `purge_lifetime` to avoid retransmissions.
/// Currently, I implement Ord as a lexiographic ordering of [TIEID, SequenceNumber]. The origination
/// time and lifetime fields are ignored for this.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct TIEHeader {
    /// ID of the tie.
    pub tie_id: TIEID,
    /// Sequence number of the tie.
    pub seq_nr: SequenceNumber,
    /// Absolute timestamp when the TIE was generated.
    pub origination_time: Option<IEEE8021ASTimeStamp>,
    /// Original lifetime when the TIE was generated.
    pub origination_lifetime: Option<LifetimeInSecs>,
}

impl PartialEq for TIEHeader {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for TIEHeader {}

impl PartialOrd for TIEHeader {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TIEHeader {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.tie_id.cmp(&other.tie_id) {
            Ordering::Equal => self.seq_nr.cmp(&other.seq_nr),
            x => x,
        }
    }
}

impl From<encoding::TIEHeader> for TIEHeader {
    fn from(value: encoding::TIEHeader) -> Self {
        TIEHeader {
            tie_id: value.tieid.into(),
            seq_nr: value.seq_nr as SequenceNumber,
            origination_time: value.origination_time.map(|x| x.into()),
            origination_lifetime: value.origination_lifetime.map(|x| x as LifetimeInSecs),
        }
    }
}

impl From<TIEHeader> for encoding::TIEHeader {
    fn from(value: TIEHeader) -> Self {
        encoding::TIEHeader {
            tieid: value.tie_id.into(),
            seq_nr: value.seq_nr as common::SeqNrType,
            origination_time: value.origination_time.map(|x| x.into()),
            origination_lifetime: value
                .origination_lifetime
                .map(|x| x as common::LifeTimeInSecType),
        }
    }
}

/// Wrapper since the values need to be unsigned and the Thrift autogenerated code is not unsigned.
/// Timestamp per IEEE 802.1AS, all values MUST be interpreted in
/// implementation as unsigned.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IEEE8021ASTimeStamp {
    pub a_s_sec: u64,
    pub a_s_nsec: Option<u32>,
}

impl TryFrom<IEEE8021ASTimeStamp> for SystemTime {
    type Error = IEEE8021ASTimeStampError;

    fn try_from(value: IEEE8021ASTimeStamp) -> Result<Self, Self::Error> {
        let duration = Duration::new(value.a_s_sec, value.a_s_nsec.unwrap_or(0));
        SystemTime::UNIX_EPOCH
            .checked_add(duration)
            .ok_or(IEEE8021ASTimeStampError)
    }
}

impl From<common::IEEE8021ASTimeStampType> for IEEE8021ASTimeStamp {
    fn from(value: common::IEEE8021ASTimeStampType) -> Self {
        IEEE8021ASTimeStamp {
            a_s_sec: value.a_s_sec as u64,
            a_s_nsec: value.a_s_nsec.map(|x| x as u32),
        }
    }
}

impl From<IEEE8021ASTimeStamp> for common::IEEE8021ASTimeStampType {
    fn from(value: IEEE8021ASTimeStamp) -> Self {
        common::IEEE8021ASTimeStampType {
            a_s_sec: value.a_s_sec as i64,
            a_s_nsec: value.a_s_nsec.map(|x| x as i32),
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Overflowed while converting to SystemTime")]
pub struct IEEE8021ASTimeStampError;

/// This wrapper exists because the Ord and Eq implementations on TIEID are probably wrong.
/// Specifically, the TIEIDs defined in `encoding` use signed integers for the fields, when they need
/// to be unsigned integers.
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
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TIEID {
    /// direction of TIE
    pub direction: TieDirection,
    /// indicates originator of the TIE
    pub originator: SystemID,
    /// type of the tie
    pub tie_type: TIESubtype,
    /// number of the tie
    pub tie_nr: TieNumber,
}

impl From<encoding::TIEID> for TIEID {
    fn from(value: encoding::TIEID) -> Self {
        TIEID {
            direction: value.direction.try_into().unwrap(),
            originator: SystemID(value.originator as u64),
            tie_type: value.tietype.try_into().unwrap(),
            tie_nr: value.tie_nr.try_into().unwrap(),
        }
    }
}

impl From<TIEID> for encoding::TIEID {
    fn from(value: TIEID) -> Self {
        encoding::TIEID {
            direction: value.direction.into(),
            originator: value.originator.into(),
            tietype: value.tie_type.into(),
            tie_nr: value.tie_nr.into(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TieDirection {
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TIESubtype {
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

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TieNumber(u32);
impl TryFrom<common::TIENrType> for TieNumber {
    type Error = String;

    fn try_from(value: common::TIENrType) -> Result<Self, Self::Error> {
        if value >= 0 {
            Ok(TieNumber(value as u32))
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
        value.0 as common::TIENrType
    }
}

/// A per-node, network-unique ID. From the spec:
/// Each RIFT node identifies itself by a valid, network wide unique number when trying to build
/// adjacencies or describing its topology. RIFT System IDs can be auto-derived or configured.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SystemID(u64);

impl SystemID {
    pub fn get(&self) -> common::SystemIDType {
        common::SystemIDType::from(*self)
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
        value.0 as common::SystemIDType
    }
}
