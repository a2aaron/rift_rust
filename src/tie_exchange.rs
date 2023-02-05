use crate::models::encoding::{
    PacketHeader, ProtocolPacket, TIDEPacket, TIEHeader, TIEPacket, TIREPacket, TIEID,
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
}

impl TieStateMachine {
    pub fn new() -> TieStateMachine {
        TieStateMachine {
            transmit_ties: TieCollection::new(),
            acknoledge_ties: TieCollection::new(),
            requested_ties: TieCollection::new(),
            retransmit_ties: TieCollection::new(),
        }
    }

    pub fn generate_tide(&mut self) {
        todo!()
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

struct TieCollection {}

impl TieCollection {
    fn new() -> TieCollection {
        TieCollection {}
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
