use std::{collections::BTreeMap, error::Error};

use crate::{
    models::{
        common::{self, TIETypeType, TieDirectionType},
        encoding::{
            PacketHeader, ProtocolPacket, TIDEPacket, TIEHeader, TIEHeaderWithLifeTime, TIEPacket,
            TIREPacket, TIEID,
        },
    },
    wrapper::SystemID,
};

const MIN_TIEID: TIEID = TIEID {
    direction: TieDirectionType::SOUTH,
    originator: 0,
    tietype: TIETypeType::T_I_E_TYPE_MIN_VALUE,
    tie_nr: 0,
};

const MAX_TIEID: TIEID = TIEID {
    direction: TieDirectionType::NORTH,
    originator: common::SystemIDType::MAX,
    tietype: TIETypeType::T_I_E_TYPE_MAX_VALUE,
    tie_nr: common::TIENrType::MAX,
};

/// I don't know if this actually makes sense to have
pub struct TieStateMachine {
    /// Collection containing all the TIEs to transmit on the adjacency.
    transmit_ties: TieCollection,
    /// Collection containing all the TIEs that have to be acknowledged on the adjacency.
    acknoledge_ties: TieCollection,
    /// Collection containing all the TIE headers that have to be requested on the adjacency.
    requested_ties: TieCollection,
    /// Collection containing all TIEs that need retransmission with the according time to
    /// retransmit
    retransmit_ties: TieCollection,
    /// Unsure what this actually is. Seems to be an ordered collection of TIEs?
    tie_db: TieCollection,
}

impl TieStateMachine {
    pub fn new() -> TieStateMachine {
        TieStateMachine {
            transmit_ties: TieCollection::new(),
            acknoledge_ties: TieCollection::new(),
            requested_ties: TieCollection::new(),
            retransmit_ties: TieCollection::new(),
            tie_db: TieCollection::new(),
        }
    }

    /// Implements section 4.2.3.3.1.2.1 TIDE Generation
    /// 4.2.3.3.1.2.1. TIDE Generation
    /// As given by timer constant, periodically generate TIDEs by:
    ///     NEXT_TIDE_ID: ID of next TIE to be sent in TIDE.
    ///     TIDE_START: Begin of TIDE packet range.
    /// a. NEXT_TIDE_ID = MIN_TIEID
    /// b. while NEXT_TIDE_ID not equal to MAX_TIEID do
    ///     1. TIDE_START = NEXT_TIDE_ID
    ///     2. HEADERS = At most TIRDEs_PER_PKT headers in TIEDB starting at NEXT_TIDE_ID or
    ///        higher that SHOULD be filtered by is_tide_entry_filtered and MUST either have a
    ///        lifetime left > 0 or have no content
    ///     3. if HEADERS is empty then START = MIN_TIEID else START = first element in HEADERS
    ///     4. if HEADERS' size less than TIRDEs_PER_PKT then END = MAX_TIEID else END = last
    ///         element in HEADERS
    ///     5. send *sorted* HEADERS as TIDE setting START and END as its range
    ///     6. NEXT_TIDE_ID = END
    /// The constant `TIRDEs_PER_PKT` SHOULD be computed per interface and used by the
    /// implementation to limit the amount of TIE headers per TIDE so the sent TIDE PDU does not
    /// exceed interface MTU.
    /// TIDE PDUs SHOULD be spaced on sending to prevent packet drops
    pub fn generate_tide(&mut self, tirdes_per_pkt: usize) -> Vec<TIDEPacket> {
        fn positive_lifetime(tie: &TIEPacket) -> bool {
            todo!()
        }

        fn no_content(tie: &TIEPacket) -> bool {
            todo!()
        }
        let mut tides = vec![];

        let mut next_tide_id = MIN_TIEID;
        while next_tide_id != MAX_TIEID {
            let mut headers = self
                .tie_db
                .ties
                .range(&next_tide_id..)
                .filter(|(_, tie)| self.is_tide_entry_filtered(tie))
                .filter(|(_, tie)| positive_lifetime(tie) || no_content(tie))
                .take(tirdes_per_pkt)
                .collect::<Vec<_>>();
            headers.sort();

            let start = if headers.is_empty() {
                MIN_TIEID
            } else {
                headers.first().unwrap().0.clone()
            };

            let end = if headers.len() < tirdes_per_pkt {
                MAX_TIEID
            } else {
                headers.last().unwrap().0.clone()
            };

            let tide = TIDEPacket {
                start_range: start,
                end_range: end.clone(),
                headers: headers
                    .iter()
                    .map(|(_, tie)| TIEHeaderWithLifeTime {
                        header: tie.header.clone(),
                        remaining_lifetime: todo!(),
                    })
                    .collect(),
            };

            tides.push(tide);
            next_tide_id = end;
        }
        tides
    }

    pub fn process_tide(&mut self, tide: &TIDEPacket) {
        todo!()
    }

    pub fn generate_tire(&mut self) {
        todo!()
    }

    pub fn process_tire(&mut self, tire: &TIREPacket) {
        todo!()
    }

    pub fn process_tie(&mut self, tie: &TIEPacket) {
        todo!()
    }

    pub fn send_ties(&mut self) {
        todo!();
    }

    /// returns whether a TIE can be flood reduced or not
    fn is_flood_reduced(&self, tie: &TIEPacket) -> bool {
        todo!()
    }

    /// returns whether a header should be propagated in TIDE according to flooding scopes.
    fn is_tide_entry_filtered(&self, tie: &TIEPacket) -> bool {
        todo!()
    }

    /// returns whether a TIE request should be propagated to neighbor or not according to flooding scopes
    fn is_request_filtered(&self, tie: &TIEPacket) -> bool {
        todo!()
    }

    /// returns whether a TIE requested be flooded to neighbor or not according to flooding scopes.
    fn is_flood_filtered(&self, tie: &TIEPacket) -> bool {
        todo!()
    }

    /// A. if not is_flood_filtered(TIE) then
    /// B.1. remove TIE from TIES_RTX if present
    ///   2. if TIE" with same key is found on TIES_ACK then
    ///      a. if TIE" is same or newer than TIE do nothing else
    ///      b. remove TIE" from TIES_ACK and add TIE to TIES_TX
    ///   3. else insert TIE into TIES_TX
    fn try_to_transmit_tie(&mut self, tie: &TIEPacket) {
        if !self.is_flood_filtered(tie) {
            self.requested_ties.remove(tie);
            if let Some(other_tie) = self.acknoledge_ties.has_key(tie) {
                // if TIE" is same or newer than TIE do nothing else
                // remove TIE" from TIES_ACK and add TIE to TIES_TX
                todo!();
            } else {
                self.transmit_ties.insert(tie);
            }
        }
    }

    /// remove TIE from all collections and then insert TIE into TIES_ACK.
    fn ack_tie(&mut self, tie: &TIEPacket) {
        self.transmit_ties.remove(tie);
        self.acknoledge_ties.remove(tie);
        self.retransmit_ties.remove(tie);
        self.requested_ties.remove(tie);
        self.acknoledge_ties.insert(tie);
    }

    /// remove TIE from all collections.
    fn tie_been_acked(&mut self, tie: &TIEPacket) {
        self.transmit_ties.remove(tie);
        self.acknoledge_ties.remove(tie);
        self.retransmit_ties.remove(tie);
        self.requested_ties.remove(tie);
    }

    // same as `tie_been_acked`.
    fn remove_from_all_queues(&mut self, tie: &TIEPacket) {
        self.tie_been_acked(tie);
    }
    // if not is_request_filtered(TIE) then remove_from_all_queues(TIE) and add to TIES_REQ.
    fn request_tie(&mut self, tie: &TIEPacket) {
        if !self.is_request_filtered(tie) {
            self.remove_from_all_queues(tie);
            self.requested_ties.insert(tie);
        }
    }
    // remove TIE from TIES_TX and then add to TIES_RTX using TIE retransmission interval.
    fn move_to_rtx_list(&mut self, tie: &TIEPacket) {
        self.transmit_ties.remove(tie);
        self.retransmit_ties.remove(tie); // TODO: retransmission interval
    }

    // remove all TIEs from TIES_REQ.
    fn clear_requests(&mut self, ties: &[TIEPacket]) {
        for tie in ties {
            self.requested_ties.remove(tie)
        }
    }

    // for self-originated TIE originate an empty or re-generate with version number higher then
    fn bump_own_tie(&mut self, tie: &TIEPacket) {
        todo!()
    }
    // the one in TIE
}

struct TieCollection {
    // TODO: The TIEID Ord implementation is probably wrong. You will need to use a wrapper struct
    // and implement one manually. Check Section 4.2.3.3 for the specification.
    ties: BTreeMap<TIEID, TIEPacket>,
}

impl TieCollection {
    fn new() -> TieCollection {
        TieCollection {
            ties: BTreeMap::new(),
        }
    }

    fn insert(&mut self, tie: &TIEPacket) {
        todo!()
    }

    fn remove(&mut self, tie: &TIEPacket) {
        todo!()
    }

    fn has_key(&self, tie: &TIEPacket) -> Option<TIEPacket> {
        todo!()
    }
}

fn make_tie() -> ProtocolPacket {
    let tie_header = PacketHeader {
        major_version: todo!(),
        minor_version: todo!(),
        sender: todo!(),
        level: todo!(),
    };
    let tie_body = TIEPacket {
        header: TIEHeader {
            tieid: TIEID {
                direction: todo!(),
                originator: todo!(),
                tietype: todo!(),
                tie_nr: todo!(),
            },
            seq_nr: todo!(),
            origination_time: todo!(),
            origination_lifetime: todo!(),
        },
        element: todo!(),
    };

    todo!();
}
