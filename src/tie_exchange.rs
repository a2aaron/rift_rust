use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    error::Error,
    ops::Bound,
    time::{Duration, SystemTime},
};

use crate::wrapper::{
    TIDEPacket, TIEHeader, TIEHeaderWithLifetime, TIEPacket, TIREPacket, TieDirection, TIEID,
};

/// I don't know if this actually makes sense to have
pub struct TieStateMachine {
    /// Collection containing all the TIEs to transmit on the adjacency.
    transmit_ties: BTreeMap<TIEID, TIEHeader>,
    /// Collection containing all the TIEs that have to be acknowledged on the adjacency.
    acknowledge_ties: BTreeMap<TIEID, TIEHeader>,
    /// Collection containing all the TIE headers that have to be requested on the adjacency.
    requested_ties: BTreeMap<TIEID, TIEHeader>,
    /// Collection containing all TIEs that need retransmission with the according time to
    /// retransmit
    retransmit_ties: BTreeMap<TIEID, TIEHeader>,
    ls_db: LinkStateDatabase,
}

impl TieStateMachine {
    pub fn new() -> TieStateMachine {
        TieStateMachine {
            transmit_ties: BTreeMap::new(),
            acknowledge_ties: BTreeMap::new(),
            requested_ties: BTreeMap::new(),
            retransmit_ties: BTreeMap::new(),
            ls_db: LinkStateDatabase::new(),
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
        fn positive_lifetime(header: &TIEHeader) -> Result<bool, Box<dyn Error>> {
            let origination_time = header.origination_time;
            let lifetime_in_secs = header.origination_lifetime;
            match (origination_time, lifetime_in_secs) {
                (Some(origination_time), Some(lifetime_in_secs)) => {
                    let origination_time: SystemTime = origination_time.try_into()?;
                    let lifetime = Duration::from_secs(lifetime_in_secs as u64);
                    let elapsed = origination_time.elapsed()?;
                    Ok(elapsed < lifetime)
                }
                _ => {
                    tracing::warn!(timestamp =? origination_time,
                        lifetime =? lifetime_in_secs,
                        "Timestamp or lifetime missing");
                    Ok(false)
                }
            }
        }

        // TODO: Interpreting "TIEDB" as "LSDB".
        // 2. HEADERS = At most TIRDEs_PER_PKT headers in TIEDB starting at NEXT_TIDE_ID or
        //    higher that SHOULD be filtered by is_tide_entry_filtered and MUST either have a
        //    lifetime left > 0 or have no content
        let mut headers = self
            .ls_db
            .ties
            .iter()
            .filter(|(_, tie)| self.is_tide_entry_filtered(tie))
            .filter(|(_, tie)| {
                let positive_lifetime = match positive_lifetime(&tie.header) {
                    Ok(x) => x,
                    Err(err) => {
                        tracing::warn!(err = err, "couldn't check lifetime");
                        false
                    }
                };
                positive_lifetime || !tie_has_content(tie)
            })
            .collect::<Vec<_>>();
        // Sorting done here so that "first element" and "last element" hopefully correspond to
        // to smallest and largest elements of the vector.
        headers.sort_by_key(|a| a.0);

        let tides = headers
            .chunks(tirdes_per_pkt)
            .map(|headers| {
                // 3. if HEADERS is empty then START = MIN_TIEID else START = first element in HEADERS
                let start_range = headers.first().map(|x| *x.0);

                // 4. if HEADERS' size less than TIRDEs_PER_PKT then END = MAX_TIEID else END = last
                //     element in HEADERS
                let end_range = if headers.len() < tirdes_per_pkt {
                    None
                } else {
                    headers.last().map(|x| *x.0)
                };

                // 5. send *sorted* HEADERS as TIDE setting START and END as its range
                TIDEPacket {
                    start_range,
                    end_range,
                    headers: headers
                        .iter()
                        .map(|(_, tie)| TIEHeaderWithLifetime::new(tie.header))
                        .collect(),
                }
            })
            .collect::<Vec<_>>();

        tides
    }

    /// Implements Section 4.2.3.3.1.2.2. TIDE Processing
    /// On reception of TIDEs the following processing is performed:
    ///     TXKEYS: Collection of TIE Headers to be sent after processing of the packet
    ///     REQKEYS: Collection of TIEIDs to be requested after processing of the packet
    ///     CLEARKEYS: Collection of TIEIDs to be removed from flood state queues
    ///     LASTPROCESSED: Last processed TIEID in TIDE
    ///     DBTIE: TIE in the LSDB if found
    /// a. LASTPROCESSED = TIDE.start_range
    /// b. for every HEADER in TIDE do
    ///     1. DBTIE = find HEADER in current LSDB
    ///     2. if HEADER < LASTPROCESSED then report error and reset adjacency and return
    ///     3. put all TIEs in LSDB where (TIE.HEADER > LASTPROCESSED and TIE.HEADER < HEADER) into
    ///        TXKEYS
    ///     4. LASTPROCESSED = HEADER
    ///     5. if DBTIE not found then
    ///         I) if originator is this node then bump_own_tie
    ///         II) else put HEADER into REQKEYS
    ///     6. if DBTIE.HEADER < HEADER then
    ///         I) if originator is this node then bump_own_tie else
    ///             i. if this is a North TIE header from a northbound neighbor then override DBTIE
    ///                in LSDB with HEADER
    ///             ii. else put HEADER into REQKEYS
    ///     7. if DBTIE.HEADER > HEADER then put DBTIE.HEADER into TXKEYS
    ///     8. if DBTIE.HEADER = HEADER then
    ///         I) if DBTIE has content already then put DBTIE.HEADER into CLEARKEYS
    ///         II) else put HEADER into REQKEYS
    /// c. put all TIEs in LSDB where (TIE.HEADER > LASTPROCESSED and TIE.HEADER <= TIDE.end_range
    ///    into TXKEYS
    /// d. for all TIEs in TXKEYS try_to_transmit_tie(TIE)
    /// e. for all TIEs in REQKEYS request_tie(TIE)
    /// f. for all TIEs in CLEARKEYS remove_from_all_queues(TIE)
    pub fn process_tide(
        &mut self,
        is_originator: bool,
        from_northbound: bool,
        tide: &TIDEPacket,
    ) -> Result<(), Box<dyn Error>> {
        let mut req_keys = vec![];
        let mut tx_keys = vec![];
        let mut clear_keys = vec![];

        // a. LASTPROCESSED = TIDE.start_range
        let mut last_processed = tide.start_range;

        // b. for every HEADER in TIDE do
        for tide_header in &tide.headers {
            // 1. DBTIE = find HEADER in current LSDB
            let db_tie = self.ls_db.find(&tide_header.header);

            // 2. if HEADER < LASTPROCESSED then report error and reset adjacency and return
            if Some(tide_header.header.tie_id) < last_processed {
                // TODO: reset adjacency
                return Err("HEADER < LASTPROCESSED".into());
            }

            // 3. put all TIEs in LSDB where (TIE.HEADER > LASTPROCESSED and TIE.HEADER < HEADER) into TXKEYS
            // TODO: Interpreting "put all TIEs ... into TXKEYS" as "put all TIE.HEADERs ... into TXKEYS"
            let range = match last_processed {
                None => (Bound::Unbounded, Bound::Excluded(tide_header.header.tie_id)),
                Some(x) => (
                    Bound::Excluded(x),
                    Bound::Excluded(tide_header.header.tie_id),
                ),
            };
            let range = self.ls_db.ties.range(range).map(|x| x.1.header);
            tx_keys.extend(range);

            // 4. LASTPROCESSED = HEADER
            last_processed = Some(tide_header.header.tie_id);

            match db_tie {
                None => {
                    // 5. if DBTIE not found then
                    if is_originator {
                        // I) if originator is this node then bump_own_tie
                        self.bump_own_tie(&tide_header.header)
                    } else {
                        // II) else put HEADER into REQKEYS
                        req_keys.push(tide_header);
                    }
                }
                Some(db_tie) => {
                    // 6. if DBTIE.HEADER < HEADER then
                    if db_tie.header < tide_header.header {
                        if is_originator {
                            // I) if originator is this node then bump_own_tie else
                            self.bump_own_tie(&tide_header.header);
                        } else {
                            // i. if this is a North TIE header from a northbound neighbor then
                            //    override DBTIE in LSDB with HEADER
                            if tide_header.header.tie_id.direction == TieDirection::North
                                && from_northbound
                            {
                                self.ls_db.replace(&db_tie, &tide_header.header);
                            } else {
                                // ii. else put HEADER into REQKEYS
                                req_keys.push(tide_header);
                            }
                        }
                    } else if db_tie.header > tide_header.header {
                        // 7. if DBTIE.HEADER > HEADER then put DBTIE.HEADER into TXKEYS
                        tx_keys.push(db_tie.header)
                    } else {
                        // 8. if DBTIE.HEADER = HEADER then
                        if tie_has_content(&db_tie) {
                            // I) if DBTIE has content already then put DBTIE.HEADER into CLEARKEYS
                            clear_keys.push(db_tie.header);
                        } else {
                            // II) else put HEADER into REQKEYS
                            req_keys.push(tide_header);
                        }
                    }
                }
            }
        }

        // c. put all TIEs in LSDB where (TIE.HEADER > LASTPROCESSED and TIE.HEADER <= TIDE.end_range
        //    into TXKEYS
        let range = match (last_processed, tide.end_range) {
            (None, None) => (Bound::Unbounded, Bound::Unbounded),
            (None, Some(end)) => (Bound::Unbounded, Bound::Included(end)),
            (Some(start), None) => (Bound::Excluded(start), Bound::Unbounded),
            (Some(start), Some(end)) => (Bound::Excluded(start), Bound::Included(end)),
        };
        for (_, tie) in self.ls_db.ties.range(range) {
            tx_keys.push(tie.header);
        }

        // d. for all TIEs in TXKEYS try_to_transmit_tie(TIE)
        for tie in tx_keys {
            self.try_to_transmit_tie(tie);
        }

        // e. for all TIEs in REQKEYS request_tie(TIE)
        for tie in req_keys {
            self.request_tie(&tie.header);
        }

        // f. for all TIEs in CLEARKEYS remove_from_all_queues(TIE)
        for tie in clear_keys {
            self.remove_from_all_queues(&tie)
        }
        Ok(())
    }

    /// 4.2.3.3.1.3.1. TIRE Generation
    /// Elements from both TIES_REQ and TIES_ACK MUST be collected and sent out as fast as feasible
    /// as TIREs. When sending TIREs with elements from TIES_REQ the `remaining_lifetime` field in
    /// `TIEHeaderWithLifeTime` MUST be set to 0 to force reflooding from the neighbor even if the
    /// TIEs seem to be same.
    pub fn generate_tire(&mut self) -> TIREPacket {
        let mut headers = BTreeSet::new();
        for (_, &header) in &self.requested_ties {
            let header = TIEHeaderWithLifetime {
                header,
                remaining_lifetime: 0,
            };
            headers.insert(header);
        }

        for (_, &header) in &self.acknowledge_ties {
            let header = TIEHeaderWithLifetime::new(header);
            headers.insert(header);
        }

        TIREPacket { headers }
    }

    /// 4.2.3.3.1.3.2. TIRE Processing
    /// On reception of TIREs the following processing is performed:
    ///     TXKEYS: Collection of TIE Headers to be send after processing of the packet
    ///     REQKEYS: Collection of TIEIDs to be requested after processing of the packet
    ///     ACKKEYS: Collection of TIEIDs that have been acked
    ///     DBTIE: TIE in the LSDB if found
    /// a. for every HEADER in TIRE do
    ///     1. DBTIE = find HEADER in current LSDB
    ///     2. if DBTIE not found then do nothing
    ///     3. if DBTIE.HEADER < HEADER then put HEADER into REQKEYS
    ///     4. if DBTIE.HEADER > HEADER then put DBTIE.HEADER into TXKEYS
    ///     5. if DBTIE.HEADER = HEADER then put DBTIE.HEADER into ACKKEYS
    /// b. for all TIEs in TXKEYS try_to_transmit_tie(TIE)
    /// c. for all TIEs in REQKEYS request_tie(TIE)
    /// d. for all TIEs in ACKKEYS tie_been_acked(TIE)
    pub fn process_tire(&mut self, tire: &TIREPacket) {
        let mut req_keys = vec![];
        let mut tx_keys = vec![];
        let mut ack_keys = vec![];
        // a. for every HEADER in TIRE do
        for tire_header in &tire.headers {
            // 1. DBTIE = find HEADER in current LSDB
            let db_tie = self.ls_db.find(&tire_header.header);
            // 2. if DBTIE not found then do nothing
            if let Some(db_tie) = db_tie {
                if db_tie.header < tire_header.header {
                    // 3. if DBTIE.HEADER < HEADER then put HEADER into REQKEYS
                    req_keys.push(tire_header);
                } else if db_tie.header > tire_header.header {
                    // 4. if DBTIE.HEADER > HEADER then put DBTIE.HEADER into TXKEYS
                    tx_keys.push(db_tie.header);
                } else {
                    // 5. if DBTIE.HEADER = HEADER then put DBTIE.HEADER into ACKKEYS
                    ack_keys.push(db_tie.header);
                }
            }
        }

        // b. for all TIEs in TXKEYS try_to_transmit_tie(TIE)
        for tie in tx_keys {
            self.try_to_transmit_tie(tie);
        }

        // c. for all TIEs in REQKEYS request_tie(TIE)
        for tie in req_keys {
            self.request_tie(&tie.header);
        }

        // d. for all TIEs in ACKKEYS tie_been_acked(TIE)
        for tie in ack_keys {
            self.tie_been_acked(&tie);
        }
    }

    /// 4.2.3.3.1.4. TIEs Processing on Flood State Adjacency
    /// On reception of TIEs the following processing is performed:
    ///     ACKTIE: TIE to acknowledge
    ///     TXTIE: TIE to transmit
    ///     DBTIE: TIE in the LSDB if found
    /// a. DBTIE = find TIE in current LSDB
    /// b. if DBTIE not found then
    ///     1. if originator is this node then bump_own_tie with a short remaining lifetime
    ///     2. else insert TIE into LSDB and ACKTIE = TIE
    /// else
    ///     1. if DBTIE.HEADER = TIE.HEADER then
    ///         i. if DBTIE has content already then ACKTIE = TIE
    ///         ii. else process like the "DBTIE.HEADER < TIE.HEADER" case
    ///     2. if DBTIE.HEADER < TIE.HEADER then
    ///         i. if originator is this node then bump_own_tie
    ///         ii. else insert TIE into LSDB and ACKTIE = TIE
    ///     3. if DBTIE.HEADER > TIE.HEADER then
    ///         i. if DBTIE has content already then TXTIE = DBTIE
    ///         ii. else ACKTIE = DBTIE
    /// c. if TXTIE is set then try_to_transmit_tie(TXTIE)
    /// d. if ACKTIE is set then ack_tie(TIE)
    pub fn process_tie(&mut self, is_originator: bool, tie: &TIEPacket) {
        let mut tx_tie = None;
        let mut ack_tie = None;

        // a. DBTIE = find TIE in current LSDB
        let db_tie = self.ls_db.find(&tie.header);

        // Convience closure--this implements the following:
        // 1. if originator is this node then bump_own_tie with a short remaining lifetime
        // 2. else insert TIE into LSDB and ACKTIE = TIE
        let mut if_originator_then_bump_else_insert_tie_and_set_acktie = || {
            if is_originator {
                // 1. if originator is this node then bump_own_tie with a short remaining lifetime
                self.bump_own_tie(&tie.header);
            } else {
                // 2. else insert TIE into LSDB and ACKTIE = TIE
                self.ls_db.insert(tie);
                ack_tie = Some(tie);
            }
        };

        match &db_tie {
            // b. if DBTIE not found then
            None => {
                // 1. if originator is this node then bump_own_tie with a short remaining lifetime
                // 2. else insert TIE into LSDB and ACKTIE = TIE
                if_originator_then_bump_else_insert_tie_and_set_acktie();
            }
            // else
            Some(db_tie) => {
                if db_tie.header == tie.header {
                    // 1. if DBTIE.HEADER = TIE.HEADER then
                    if tie_has_content(&db_tie) {
                        // i. if DBTIE has content already then ACKTIE = TIE
                        ack_tie = Some(tie);
                    } else {
                        // ii. else process like the "DBTIE.HEADER < TIE.HEADER" case
                        if_originator_then_bump_else_insert_tie_and_set_acktie();
                    }
                } else if db_tie.header < tie.header {
                    // 2. if DBTIE.HEADER < TIE.HEADER then
                    // i. if originator is this node then bump_own_tie
                    // ii. else insert TIE into LSDB and ACKTIE = TIE
                    if_originator_then_bump_else_insert_tie_and_set_acktie();
                } else {
                    // 3. if DBTIE.HEADER > TIE.HEADER then
                    if tie_has_content(&db_tie) {
                        // i. if DBTIE has content already then TXTIE = DBTIE
                        tx_tie = Some(db_tie);
                    } else {
                        // ii. else ACKTIE = DBTIE
                        ack_tie = Some(db_tie);
                    }
                }
            }
        }
        // c. if TXTIE is set then try_to_transmit_tie(TXTIE)
        if let Some(tie) = tx_tie {
            self.try_to_transmit_tie(tie.header);
        }

        // d. if ACKTIE is set then ack_tie(TIE)
        if let Some(tie) = ack_tie {
            self.ack_tie(tie);
        }
    }

    pub fn send_ties(&mut self) {
        todo!();
    }

    /// Seemingly not used in the spec?
    /// returns whether a TIE can be flood reduced or not
    fn _is_flood_reduced(&self, _tie: &TIEPacket) -> bool {
        todo!()
    }

    /// returns whether a header should be propagated in TIDE according to flooding scopes.
    fn is_tide_entry_filtered(&self, tie: &TIEPacket) -> bool {
        todo!()
    }

    /// returns whether a TIE request should be propagated to neighbor or not according to flooding scopes
    fn is_request_filtered(&self, tie: &TIEHeader) -> bool {
        todo!()
    }

    /// returns whether a TIE requested be flooded to neighbor or not according to flooding scopes.
    fn is_flood_filtered(&self, tie: &TIEHeader) -> bool {
        todo!()
    }

    /// TODO: What does "TIE" with the same key" mean? Should acknowledge_ties be a map and not a set?
    /// A. if not is_flood_filtered(TIE) then
    /// B.1. remove TIE from TIES_RTX if present
    ///   2. if TIE" with same key is found on TIES_ACK then
    ///      a. if TIE" is same or newer than TIE do nothing else
    ///      b. remove TIE" from TIES_ACK and add TIE to TIES_TX
    ///   3. else insert TIE into TIES_TX
    fn try_to_transmit_tie(&mut self, tie: TIEHeader) {
        if !self.is_flood_filtered(&tie) {
            self.requested_ties.remove(&tie.tie_id);
            if let Entry::Occupied(entry) = self.acknowledge_ties.entry(tie.tie_id) {
                let other_tie = entry.get();
                // a. if TIE" is same or newer than TIE do nothing else
                // b. remove TIE" from TIES_ACK and add TIE to TIES_TX
                if tie.seq_nr > other_tie.seq_nr {
                    entry.remove_entry();
                    self.transmit_ties.insert(tie.tie_id, tie);
                }
                todo!();
            } else {
                self.transmit_ties.insert(tie.tie_id, tie);
            }
        }
    }

    /// remove TIE from all collections and then insert TIE into TIES_ACK.
    fn ack_tie(&mut self, tie: &TIEPacket) {
        self.transmit_ties.remove(&tie.header.tie_id);
        self.acknowledge_ties.remove(&tie.header.tie_id);
        self.retransmit_ties.remove(&tie.header.tie_id);
        self.requested_ties.remove(&tie.header.tie_id);
        self.acknowledge_ties.insert(tie.header.tie_id, tie.header);
    }

    /// remove TIE from all collections.
    fn tie_been_acked(&mut self, tie: &TIEHeader) {
        self.transmit_ties.remove(&tie.tie_id);
        self.acknowledge_ties.remove(&tie.tie_id);
        self.retransmit_ties.remove(&tie.tie_id);
        self.requested_ties.remove(&tie.tie_id);
    }

    /// same as `tie_been_acked`.
    fn remove_from_all_queues(&mut self, tie: &TIEHeader) {
        self.tie_been_acked(tie);
    }
    /// if not is_request_filtered(TIE) then remove_from_all_queues(TIE) and add to TIES_REQ.
    fn request_tie(&mut self, tie: &TIEHeader) {
        if !self.is_request_filtered(tie) {
            self.remove_from_all_queues(tie);
            self.requested_ties.insert(tie.tie_id, tie.clone());
        }
    }
    /// Seemingly not used in the spec?
    /// remove TIE from TIES_TX and then add to TIES_RTX using TIE retransmission interval.
    fn _move_to_rtx_list(&mut self, tie: &TIEPacket) {
        self.transmit_ties.remove(&tie.header.tie_id);
        self.retransmit_ties.remove(&tie.header.tie_id);
        todo!(); // TODO: retransmission interval
    }

    /// Seemingly not used in the spec?
    /// remove all TIEs from TIES_REQ.
    fn _clear_requests(&mut self, ties: &[TIEPacket]) {
        for tie in ties {
            self.requested_ties.remove(&tie.header.tie_id);
        }
    }

    /// NOTE: this seems to be only ever called in contexts where the TIE happens to be
    /// self-originiated, so a check here is not needed.
    /// for self-originated TIE originate an empty or re-generate with version number higher then
    /// the one in TIE
    fn bump_own_tie(&mut self, tie: &TIEHeader) {
        todo!()
    }
}

fn tie_has_content(tie: &TIEPacket) -> bool {
    todo!()
}

struct LinkStateDatabase {
    ties: BTreeMap<TIEID, TIEPacket>,
}

impl LinkStateDatabase {
    fn new() -> LinkStateDatabase {
        LinkStateDatabase {
            ties: BTreeMap::new(),
        }
    }

    fn find(&self, header: &TIEHeader) -> Option<TIEPacket> {
        todo!()
    }

    fn replace(&self, db_header: &TIEPacket, header: &TIEHeader) {
        todo!()
    }

    fn insert(&mut self, tie: &TIEPacket) {
        todo!()
    }
}
