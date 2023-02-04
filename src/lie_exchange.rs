use std::{
    collections::{HashMap, VecDeque},
    io,
    net::IpAddr,
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    models::{
        common::{
            self, LinkIDType, MTUSizeType, SystemIDType, UDPPortType, DEFAULT_BANDWIDTH,
            DEFAULT_LIE_HOLDTIME, DEFAULT_ZTP_HOLDTIME, ILLEGAL_SYSTEM_I_D,
            MULTIPLE_NEIGHBORS_LIE_HOLDTIME_MULTIPLER,
        },
        encoding::{
            self, LIEPacket, PacketHeader, ProtocolPacket, PROTOCOL_MAJOR_VERSION,
            PROTOCOL_MINOR_VERSION,
        },
    },
    network::{LinkSocket, NodeInfo},
    topology::SystemID,
};

pub const LEAF_LEVEL: u8 = common::LEAF_LEVEL as u8;

/// The state machine for LIE exchange. This struct accepts external events, and expects the consumer
/// of this struct to provide those external events (this is to say, events such as TimerTick are not
/// automatically handled and should be pushed manually.) This struct does store internal timers however.
#[derive(Serialize)]
pub struct LieStateMachine {
    /// Determines if a link is logically present in the topology. If the LIEState is ThreeWay, then
    /// the link is logically present. Otherwise, it is not.
    lie_state: LieState,
    #[serde(skip)]
    external_event_queue: VecDeque<LieEvent>,
    #[serde(skip)]
    chained_event_queue: VecDeque<LieEvent>,
    /// This node's level, which can be changed by the ZTP FSM or set to a configured value.
    level: Level,
    /// from spec:  Set of nodes offering HAL VOLs
    /// This, along with `highest_available_level` and `highest_adjacency_threeway` are set by
    /// LieEvent::HAL/HAT/HALSChanged and are sent by the ZTP FSM usually. For some reason, only the
    /// HAT seems to be used in the LIE FSM, but it is included for completeness. Note that if ZTP
    /// is not active, then the HAT and HAL will always be Level::Undefined (and hence have no effect).
    highest_available_level_systems: HALS,
    // from spec: Highest defined level value seen from all VOLs received.
    highest_available_level: Level,
    /// from spec: Highest neighbor level of all the formed ThreeWay adjacencies for the node.
    highest_adjacency_threeway: Level,
    /// The neighbor value, which is set by PROCESS_LIE and checked by SEND_LIE. If this value is
    /// Some, then a neighbor has been observed and will be sent out during SEND_LIE to reflect back
    /// to the node on the other end of the Link.
    neighbor: Option<Neighbor>,
    /// A tuple containing the time at which the most recent valid LIE was received along with the
    /// holdtime that LIE packet had. This value is updated each time a valid LIE is received on the
    /// link (see [LieStateMachine::process_lie] for more detail). This controls how long the LIE
    /// is considered to be alive before it "expires", which in turn determines how long the LIE FSM
    /// will remaining in TwoWay or ThreeWay before automatically PUSHing HoldtimeExpired and reverting
    /// to OneWay..
    #[serde(skip)]
    last_valid_lie: Option<(Timer, PacketHeader, LIEPacket)>,
    /// The time at which the multiple neighbors timer was started
    #[serde(skip)]
    multiple_neighbors_timer: Timer,
}

impl LieStateMachine {
    /// Create a new LieStateMachine. The `configured_level` determines the level that the state machine
    /// will start in. If ZTP is not used, then typically `configured_level` is not `Level::Undefined`.
    /// Otherwise, if ZTP is used, then `configured_level` is typically `Level::Undefined`.
    pub fn new(configured_level: Level) -> LieStateMachine {
        LieStateMachine {
            lie_state: LieState::OneWay,
            external_event_queue: VecDeque::new(),
            chained_event_queue: VecDeque::new(),
            level: configured_level,
            highest_available_level_systems: HALS,
            highest_available_level: Level::Undefined,
            highest_adjacency_threeway: Level::Undefined,
            neighbor: None,
            last_valid_lie: None,
            multiple_neighbors_timer: Timer::new(Duration::from_secs(
                MULTIPLE_NEIGHBORS_LIE_HOLDTIME_MULTIPLER as u64 * DEFAULT_LIE_HOLDTIME as u64,
            )),
        }
    }

    /// Process a external events, if there exist any events in the event queue. Note that this
    /// also processes any events pushed by the PUSH procedure, so the `chained_event_queue` will
    /// be empty both before and after this call.
    pub fn process_external_events(
        &mut self,
        socket: &mut LinkSocket,
        node_info: &NodeInfo,
        ztp_fsm: &mut ZtpStateMachine,
    ) -> io::Result<()> {
        assert!(self.chained_event_queue.is_empty());
        while !self.external_event_queue.is_empty() {
            self.process_external_event(socket, node_info, ztp_fsm)?;
        }
        assert!(self.chained_event_queue.is_empty());
        Ok(())
    }

    /// Process a single external event, if there exists an event in the event queue. Note that this
    /// also processes any events pushed by the PUSH procedure, so the `chained_event_queue` will
    /// be empty both before and after this call.
    fn process_external_event(
        &mut self,
        socket: &mut LinkSocket,
        node_info: &NodeInfo,
        ztp_fsm: &mut ZtpStateMachine,
    ) -> io::Result<()> {
        let _span = tracing::info_span!(
            target: "LIE_FSM",
            "process_external_event",
            state =? self.lie_state,
            level =? self.level,
        )
        .entered();

        assert!(self.chained_event_queue.is_empty());
        if let Some(event) = self.external_event_queue.pop_front() {
            let _span = tracing::trace_span!(
                "external_event_queue",
                event = event.name(),
                state =? self.lie_state,
            )
            .entered();
            let new_state = self.process_lie_event(event, socket, node_info, ztp_fsm)?;
            self.transition_to(new_state);
        }

        // Drain the chained event queue, if an external event caused some events to be pushed.
        while let Some(event) = self.chained_event_queue.pop_front() {
            let _span = tracing::trace_span!(
                "chained_event_queue",
                event = event.name(),
                state =? self.lie_state,
            )
            .entered();
            let new_state = self.process_lie_event(event, socket, node_info, ztp_fsm)?;
            self.transition_to(new_state);
        }
        Ok(())
    }

    /// Set the current state to the new state. If this would cause the state to enter LieState::OneWay,
    /// then CLEANUP is also performed. If the current state is already equal to the new state, noop.
    fn transition_to(&mut self, new_state: LieState) {
        if new_state != self.lie_state {
            tracing::trace!(from =? self.lie_state, to =? new_state, "state transition",);
            // on Entry into OneWay: CLEANUP
            if new_state == LieState::OneWay {
                self.cleanup();
            }
            if new_state == LieState::ThreeWay {
                tracing::info!(
                    neighbor =? self.neighbor.as_ref().unwrap(),
                    "gained neighbor"
                );
            }

            self.lie_state = new_state;
        }
    }

    /// Push an external event onto the LIEEvent queue.
    pub fn push_external_event(&mut self, event: LieEvent) {
        tracing::trace!(event = event.name(), "pushing external event");
        self.external_event_queue.push_back(event);
    }

    // process the given LIE event. The return value is the LieState to transition into next.
    fn process_lie_event(
        &mut self,
        event: LieEvent,
        socket: &mut LinkSocket,
        node_info: &NodeInfo,
        ztp_fsm: &mut ZtpStateMachine,
    ) -> io::Result<LieState> {
        let new_state = match self.lie_state {
            LieState::OneWay => match event {
                LieEvent::TimerTick => {
                    self.push(LieEvent::SendLie);
                    LieState::OneWay
                }
                LieEvent::UnacceptableHeader => LieState::OneWay,
                LieEvent::LevelChanged(new_level) => {
                    // update level with event value, PUSH SendLie event
                    self.update_level(new_level);
                    self.push(LieEvent::SendLie);
                    LieState::OneWay
                }
                LieEvent::NeighborChangedMinorFields => LieState::OneWay,
                LieEvent::NeighborChangedLevel => LieState::OneWay,
                LieEvent::NewNeighbor => {
                    self.push(LieEvent::SendLie); // PUSH SendLie
                    LieState::TwoWay
                }
                LieEvent::HoldtimeExpired => {
                    LieStateMachine::expire_offer(ztp_fsm, node_info.system_id);
                    LieState::OneWay
                }
                LieEvent::HALSChanged(new_hals) => {
                    self.store_hals(new_hals); // store HALS
                    LieState::OneWay
                }
                LieEvent::NeighborChangedAddress => LieState::OneWay,
                LieEvent::LieRcvd(address, lie_header, lie_packet) => {
                    // PROCESS_LIE
                    self.process_lie_procedure(
                        address,
                        &lie_header,
                        &lie_packet,
                        node_info.system_id,
                        socket.local_link_id,
                        socket.mtu,
                    );
                    LieState::OneWay
                }
                LieEvent::ValidReflection => LieState::ThreeWay,
                LieEvent::SendLie => {
                    self.send_lie_procedure(socket, node_info)?; // SEND_LIE
                    LieState::OneWay
                }
                LieEvent::UpdateZTPOffer => {
                    self.send_offer(ztp_fsm);
                    LieState::OneWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_hat(new_hat); // store HAT
                    LieState::OneWay
                }
                LieEvent::MultipleNeighbors => {
                    // start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
                    self.start_multiple_neighbors_timer();
                    LieState::MultipleNeighborsWait
                }
                LieEvent::MTUMismatch => LieState::OneWay,
                LieEvent::FloodLeadersChanged => {
                    // update `you_are_flood_repeater` LIE elements based on flood leader election results
                    self.update_you_are_flood_repeater();
                    LieState::OneWay
                }
                LieEvent::NeighborDroppedReflection => LieState::OneWay,
                LieEvent::HALChanged(new_hal) => {
                    self.store_hal(new_hal); // store new HAL
                    LieState::OneWay
                }
                // Illegal State Transitions
                LieEvent::MultipleNeighborsDone => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
            },
            LieState::TwoWay => match event {
                LieEvent::NeighborChangedAddress => LieState::OneWay,
                LieEvent::LieRcvd(address, lie_header, lie_packet) => {
                    // PROCESS_LIE
                    self.process_lie_procedure(
                        address,
                        &lie_header,
                        &lie_packet,
                        node_info.system_id,
                        socket.local_link_id,
                        socket.mtu,
                    );
                    LieState::TwoWay
                }
                LieEvent::UpdateZTPOffer => {
                    self.send_offer(ztp_fsm); // send offer to ZTP FSM
                    LieState::TwoWay
                }
                LieEvent::HoldtimeExpired => {
                    LieStateMachine::expire_offer(ztp_fsm, node_info.system_id);
                    LieState::OneWay
                }
                LieEvent::MTUMismatch => LieState::OneWay,
                LieEvent::UnacceptableHeader => LieState::OneWay,
                LieEvent::ValidReflection => LieState::ThreeWay,
                LieEvent::SendLie => {
                    self.send_lie_procedure(socket, node_info)?; // SEND_LIE
                    LieState::TwoWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_hat(new_hat); // store HAT
                    LieState::TwoWay
                }
                LieEvent::HALChanged(new_hal) => {
                    self.store_hal(new_hal); // store new HAL
                    LieState::TwoWay
                }
                LieEvent::LevelChanged(new_level) => {
                    // update level with event value
                    self.update_level(new_level);
                    LieState::TwoWay
                }
                LieEvent::FloodLeadersChanged => {
                    // update `you_are_flood_repeater` LIE elements based on flood leader election results
                    self.update_you_are_flood_repeater();
                    LieState::TwoWay
                }
                LieEvent::NewNeighbor => {
                    self.send_lie_procedure(socket, node_info)?; // PUSH SendLie event
                    LieState::MultipleNeighborsWait
                }
                LieEvent::TimerTick => {
                    // PUSH SendLie event, if last valid LIE was received more than `holdtime` ago
                    // as advertised by neighbor then PUSH HoldtimeExpired event
                    self.push(LieEvent::SendLie);
                    if self.is_lie_expired() {
                        self.push(LieEvent::HoldtimeExpired);
                    }
                    LieState::TwoWay
                }
                LieEvent::NeighborChangedLevel => LieState::OneWay,
                LieEvent::MultipleNeighbors => {
                    // start multiple neighbors timer with interval
                    // `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
                    self.start_multiple_neighbors_timer();
                    LieState::MultipleNeighborsWait
                }
                LieEvent::HALSChanged(new_hals) => {
                    self.store_hals(new_hals); // store HALS
                    LieState::TwoWay
                }
                // Illegal State Transitions
                LieEvent::NeighborDroppedReflection => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
                LieEvent::NeighborChangedMinorFields => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
                LieEvent::MultipleNeighborsDone => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
            },
            LieState::ThreeWay => match event {
                LieEvent::NeighborChangedAddress => LieState::OneWay,
                LieEvent::ValidReflection => LieState::ThreeWay,
                LieEvent::HoldtimeExpired => {
                    LieStateMachine::expire_offer(ztp_fsm, node_info.system_id);
                    LieState::OneWay
                }
                LieEvent::UnacceptableHeader => LieState::OneWay,
                LieEvent::NeighborDroppedReflection => LieState::TwoWay,
                LieEvent::HALChanged(new_hal) => {
                    self.highest_available_level = new_hal; // store new HAL
                    LieState::ThreeWay
                }
                LieEvent::MultipleNeighbors => {
                    // start multiple neighbors timer with interval
                    // `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
                    self.start_multiple_neighbors_timer();
                    LieState::MultipleNeighborsWait
                }
                LieEvent::LevelChanged(new_level) => {
                    self.level = new_level; // update level with event value
                    LieState::OneWay
                }
                LieEvent::HALSChanged(new_hals) => {
                    self.highest_available_level_systems = new_hals;
                    LieState::ThreeWay
                }
                LieEvent::TimerTick => {
                    // PUSH SendLie event, if last valid LIE was received more than `holdtime` ago as advertised by neighbor then PUSH HoldtimeExpired event
                    self.push(LieEvent::SendLie);
                    if self.is_lie_expired() {
                        self.push(LieEvent::HoldtimeExpired);
                    }
                    LieState::ThreeWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_hat(new_hat); // store HAT
                    LieState::ThreeWay
                }
                LieEvent::UpdateZTPOffer => {
                    self.send_offer(ztp_fsm); // send offer to ZTP FSM
                    LieState::ThreeWay
                }
                LieEvent::LieRcvd(address, lie_header, lie_packet) => {
                    self.process_lie_procedure(
                        address,
                        &lie_header,
                        &lie_packet,
                        node_info.system_id,
                        socket.local_link_id,
                        socket.mtu,
                    ); // PROCESS_LIE
                    LieState::ThreeWay
                }
                LieEvent::NeighborChangedLevel => LieState::OneWay,
                LieEvent::SendLie => {
                    self.send_lie_procedure(socket, node_info)?; // SEND_LIE
                    LieState::ThreeWay
                }
                LieEvent::FloodLeadersChanged => {
                    // update `you_are_flood_repeater` LIE elements based on flood leader election results, PUSH SendLie
                    self.update_you_are_flood_repeater();
                    LieState::ThreeWay
                }
                LieEvent::MTUMismatch => LieState::OneWay,
                // Illegal state transitions
                LieEvent::NewNeighbor => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
                LieEvent::NeighborChangedMinorFields => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),

                LieEvent::MultipleNeighborsDone => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
            },
            LieState::MultipleNeighborsWait => match event {
                LieEvent::HoldtimeExpired => {
                    LieStateMachine::expire_offer(ztp_fsm, node_info.system_id);
                    LieState::MultipleNeighborsWait
                }
                LieEvent::LieRcvd(_, _, _) => LieState::MultipleNeighborsWait,
                LieEvent::NeighborDroppedReflection => LieState::MultipleNeighborsWait,
                LieEvent::MTUMismatch => LieState::MultipleNeighborsWait,
                // not included
                // LieEvent::NeighborChangedBFDCapability => LieState::MultipleNeighborsWait
                LieEvent::LevelChanged(new_level) => {
                    self.update_level(new_level); // update level with event value
                    LieState::OneWay
                }
                LieEvent::SendLie => LieState::MultipleNeighborsWait,
                LieEvent::UpdateZTPOffer => {
                    self.send_offer(ztp_fsm); // send offer to ZTP FSM
                    LieState::MultipleNeighborsWait
                }
                LieEvent::MultipleNeighborsDone => LieState::OneWay,
                LieEvent::HATChanged(new_hat) => {
                    self.store_hat(new_hat); // store HAT
                    LieState::MultipleNeighborsWait
                }
                LieEvent::NeighborChangedAddress => LieState::MultipleNeighborsWait,
                LieEvent::HALSChanged(new_hals) => {
                    self.store_hals(new_hals); // store HALS
                    LieState::MultipleNeighborsWait
                }
                LieEvent::HALChanged(new_hal) => {
                    self.store_hal(new_hal); // store new HAL
                    LieState::MultipleNeighborsWait
                }
                LieEvent::MultipleNeighbors => {
                    // start multiple neighbors timer with interval
                    // `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
                    self.start_multiple_neighbors_timer();
                    LieState::MultipleNeighborsWait
                }
                LieEvent::FloodLeadersChanged => {
                    // update `you_are_flood_repeater` LIE elements based on flood leader election results
                    self.update_you_are_flood_repeater();
                    LieState::MultipleNeighborsWait
                }
                LieEvent::ValidReflection => LieState::MultipleNeighborsWait,
                LieEvent::TimerTick => {
                    // check MultipleNeighbors timer, if timer expired PUSH MultipleNeighborsDone
                    if self.multiple_neighbors_timer.is_expired() {
                        self.push(LieEvent::MultipleNeighborsDone);
                    };
                    LieState::MultipleNeighborsWait
                }
                LieEvent::UnacceptableHeader => LieState::MultipleNeighborsWait,
                // Illegal state transitions
                LieEvent::NewNeighbor => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
                LieEvent::NeighborChangedLevel => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
                LieEvent::NeighborChangedMinorFields => unreachable!(
                    "event {} cannot occur in {:?}",
                    event.name(),
                    self.lie_state
                ),
            },
        };
        Ok(new_state)
    }

    // implements the "PROCESS_LIE" procedure
    fn process_lie_procedure(
        &mut self,
        // The address the incoming LIE packet was sent on.
        address: IpAddr,
        // The header of the incoming LIE packet.
        lie_header: &PacketHeader,
        // The body of the incoming LIE packet.
        lie_packet: &LIEPacket,
        // The system ID of the socket that received the LIE.
        system_id: SystemID,
        // The local link ID of the socket that received the LIE.
        local_link_id: LinkIDType,
        // The MTU of the socket that received the LIE.
        socket_mtu: usize,
    ) {
        tracing::trace!("PROCESS_LIE procedure");
        let lie_level: Level = lie_header.level.into();

        // 1. if LIE has major version not equal to this node's *or*
        //       system ID equal to this node's system ID or `IllegalSystemID`
        //    then CLEANUP
        if lie_header.major_version != PROTOCOL_MAJOR_VERSION
            || lie_header.sender == system_id.get()
            || lie_header.sender == ILLEGAL_SYSTEM_I_D
        {
            self.cleanup();
            return;
        }

        if lie_packet.link_mtu_size != Some(socket_mtu as MTUSizeType) {
            // 2. if LIE has non matching MTUs
            //    then CLEANUP, PUSH UpdateZTPOffer, PUSH MTUMismatch
            self.cleanup();
            self.push(LieEvent::UpdateZTPOffer);
            self.push(LieEvent::MTUMismatch);
            return;
        }

        // At this point, the LIE packet is considered valid. Section 4.2.2 defines a "valid" neighbor as one which
        // satisfies the following conditions:
        // 1. the neighboring node is running the same major schema version as indicated in the
        //    `major_version` element in `PacketHeader` *and*
        // 2. the neighboring node uses a valid System ID (i.e. value different from `IllegalSystemID`)
        //    in `sender` element in `PacketHeader` *and*
        // 3. the neighboring node uses a different System ID than the node itself
        // 4. the advertised MTUs in `LiePacket` element match on both sides *and*
        // 5. both nodes advertise defined level values in `level` element in `PacketHeader` *and*
        // 6. [
        //      i) the node is at `leaf_level` value and has no ThreeWay adjacencies already to nodes
        //         at Highest Adjacency ThreeWay (HAT as defined later in Section 4.2.7.1) with level
        //         different than the adjacent node *or
        //      ii) the node is not at `leaf_level` value and the neighboring node is at `leaf_level` value *or*
        //      iii) both nodes are at `leaf_level` values *and* both indicate support for Section 4.3.9 *or*
        //      iv) neither node is at `leaf_level` value and the neighboring node is at most one level difference away
        // ]
        // The spec, when defining a "valid LIE" and says "passing all checks for adjacency formation
        // while disregarding all clauses involving level values" (4.2.7.1, Valid Offered Level (VOL))
        self.last_valid_lie = {
            let mut timer = Timer::new(Duration::from_secs(lie_packet.holdtime as u64));
            timer.start();
            Some((timer, lie_header.clone(), lie_packet.clone()))
        };

        // 3. if LIE has undefined level OR
        //       this node's level is undefined OR
        //       this node is a leaf and remote level is lower than HAT OR
        //       (LIE's level is not leaf AND its difference is more than one from this node's level)
        //    then CLEANUP, PUSH UpdateZTPOffer, PUSH UnacceptableHeader
        // NOTE: Spec here, as written, produces a somewhat nonsensical implementation and conflicts
        // with what is said in Section 4.2.2. We instead go with what Section 4.2.2, since this prevents
        // the nonsensical behavior of disallowing almost all formations between non-leaf nodes and
        // leaf nodes.
        let (accept_lie, reason) = match (self.level, lie_level) {
            // 5.   both nodes advertise defined level values in `level` element in `PacketHeader`
            (_, Level::Undefined) => (false, "remote level undefined (rule 5)"),
            (Level::Undefined, _) => (false, "local level undefined (rule 5)"),
            (Level::Value(our_level), Level::Value(remote_level)) => {
                let local_is_leaf = our_level == LEAF_LEVEL;
                let remote_is_leaf = remote_level == LEAF_LEVEL;
                let allow_east_west = false; // TODO: Section 4.3.9 - East - West connections.
                let remote_below_hat = match self.highest_adjacency_threeway {
                    // if our HAT is undefined, then we have no adjacencys. Therefore, the remote's
                    // level can't possibly be below the HAT.
                    Level::Undefined => false,
                    Level::Value(hat) => remote_level == hat,
                };
                let level_diff = u8::abs_diff(remote_level, our_level);

                // 6.i. the node is at `leaf_level` value and has no ThreeWay adjacencies already to nodes
                //      at Highest Adjacency ThreeWay (HAT as defined later in Section 4.2.7.1) with level
                //      different than the adjacent node
                if local_is_leaf && !remote_below_hat {
                    (
                        true,
                        "this node is leaf and remote is equal to HAT (or HAT is undefined)",
                    )
                }
                // 6.ii. the node is not at `leaf_level` value and the neighboring node is at `leaf_level` value
                else if !local_is_leaf && remote_is_leaf {
                    (true, "local is not leaf and remote is leaf")
                }
                // 6.iii. both nodes are at `leaf_level` values *and* both indicate support for Section 4.3.9
                else if local_is_leaf && remote_is_leaf && allow_east_west {
                    (true, "local and remote are leaves and east-west is enabled")
                }
                // 6.iv. neither node is at `leaf_level` value and the neighboring node is at most one level difference away
                else if !local_is_leaf && !remote_is_leaf && level_diff <= 1 {
                    (true, "neither is leaf and are within one level")
                } else {
                    (false, "no subclause of rule 6 was satisfied")
                }
            }
        };
        if !accept_lie {
            self.cleanup();
            tracing::debug!(
                local_level =? self.level,
                remote_level =? lie_level,
                hat =? self.highest_adjacency_threeway,
                reason = reason,
                "rejecting LIE packet (UnacceptableHeader)"
            );
            self.push(LieEvent::UpdateZTPOffer);
            self.push(LieEvent::UnacceptableHeader);
            return;
        }

        // 4. PUSH UpdateZTPOffer, construct temporary new neighbor structure with values from LIE,
        self.push(LieEvent::UpdateZTPOffer);
        let new_neighbor = Neighbor {
            name: lie_packet.name.clone(), // TODO: avoid an allocation here?
            system_id: lie_header.sender,
            local_link_id: lie_packet.local_id,
            level: lie_header.level.into(),
            address,
            flood_port: lie_packet.flood_port,
        };

        // if no current neighbor exists
        // then set neighbor to new neighbor, PUSH NewNeighbor event, CHECK_THREE_WAY else
        //   1. if current neighbor system ID differs from LIE's system ID
        //     then PUSH MultipleNeighbors else
        //   2. if current neighbor stored level differs from LIE's level
        //      then PUSH NeighborChangedLevel else
        //   3. if current neighbor stored IPv4/v6 address differs from LIE's address
        //      then PUSH NeighborChangedAddress else
        //   4. if any of neighbor's flood address port, name, local LinkID changed
        //      then PUSH NeighborChangedMinorFields
        // 5. CHECK_THREE_WAY
        match &self.neighbor {
            None => {
                self.neighbor = Some(new_neighbor);
                self.push(LieEvent::NewNeighbor);
                self.check_three_way(&lie_packet, system_id, local_link_id);
            }
            Some(curr_neighbor) => {
                if curr_neighbor.system_id != new_neighbor.system_id {
                    self.push(LieEvent::MultipleNeighbors);
                } else if curr_neighbor.level != new_neighbor.level {
                    self.push(LieEvent::NeighborChangedLevel);
                } else if curr_neighbor.address != new_neighbor.address {
                    self.push(LieEvent::NeighborChangedAddress);
                } else if curr_neighbor.flood_port != new_neighbor.flood_port
                    || curr_neighbor.name != new_neighbor.name
                    || curr_neighbor.local_link_id != new_neighbor.local_link_id
                {
                    self.push(LieEvent::NeighborChangedMinorFields);
                } else {
                    self.check_three_way(&lie_packet, system_id, local_link_id);
                }
            }
        }
    }

    // implements the "CHECK_THREE_WAY" procedure
    // CHECK_THREE_WAY: if current state is OneWay do nothing else
    // 1. if LIE packet does not contain neighbor
    //    then if current state is ThreeWay
    //         then PUSH NeighborDroppedReflection else
    // 2. if packet reflects this system's ID and local port and state is ThreeWay
    //    then PUSH event ValidReflection
    //    else PUSH event MultipleNeighbors
    /*
    Spec is wrong here! We instead implement
    ```py
    def check_three_way(self):
    # Section B.1.5
    # CHANGE: This is a little bit different from the specification
    # (see comment [CheckThreeWay])
    if self.fsm.state == self.State.ONE_WAY:
        pass
    elif self.fsm.state == self.State.TWO_WAY:
        if self.neighbor_lie.neighbor_system_id is None:
            pass
        elif self.check_reflection():
            self.fsm.push_event(self.Event.VALID_REFLECTION)
        else:
            self.fsm.push_event(self.Event.MULTIPLE_NEIGHBORS)
    else: # state is THREE_WAY
        if self.neighbor_lie.neighbor_system_id is None:
            self.fsm.push_event(self.Event.NEIGHBOR_DROPPED_REFLECTION)
        elif self.check_reflection():
            pass
        else:
            self.fsm.push_event(self.Event.MULTIPLE_NEIGHBORS)
    ```
     */
    fn check_three_way(
        &mut self,
        packet: &LIEPacket,
        // The system ID of the socket that that received the LIE.
        system_id: SystemID,
        // The local link ID of the socket that received the LIE.
        local_link_id: LinkIDType,
    ) {
        match (self.lie_state, &packet.neighbor) {
            (LieState::OneWay, _) => (),
            (LieState::TwoWay, None) => (),
            (LieState::TwoWay, Some(neighbor)) => {
                if neighbor.originator == system_id.get() && neighbor.remote_id == local_link_id {
                    self.push(LieEvent::ValidReflection);
                } else {
                    self.push(LieEvent::MultipleNeighbors);
                }
            }
            (LieState::ThreeWay, None) => self.push(LieEvent::NeighborDroppedReflection),
            (LieState::ThreeWay, Some(_)) => (),
            (LieState::MultipleNeighborsWait, _) => (),
        }
    }

    // implements the "SEND_LIE" procedure.
    // SEND_LIE:
    // 1. create and send a new LIE packet reflecting the neighbor if known and valid and
    // 2. setting the necessary `not_a_ztp_offer` variable if level was derived from last
    //    known neighbor on this interface and
    // 3. setting `you_are_not_flood_repeater` to computed value
    fn send_lie_procedure(&self, socket: &mut LinkSocket, node_info: &NodeInfo) -> io::Result<()> {
        let neighbor = match &self.neighbor {
            Some(neighbor) => Some(encoding::Neighbor {
                originator: neighbor.system_id,
                remote_id: neighbor.local_link_id,
            }),
            None => None,
        };

        let header = PacketHeader {
            major_version: PROTOCOL_MAJOR_VERSION,
            minor_version: PROTOCOL_MINOR_VERSION,
            sender: node_info.system_id.get(),
            level: self.level.into(),
        };

        // TODO: fill in these values with real data, instead of None
        let lie_packet = LIEPacket {
            name: node_info.node_name.clone(),
            local_id: socket.local_link_id as common::LinkIDType,
            flood_port: socket.flood_port() as common::UDPPortType,
            link_mtu_size: Some(socket.mtu as MTUSizeType),
            link_bandwidth: Some(DEFAULT_BANDWIDTH),
            neighbor,
            pod: None,
            node_capabilities: encoding::NodeCapabilities {
                protocol_minor_version: PROTOCOL_MINOR_VERSION,
                flood_reduction: None,
                hierarchy_indications: None,
                auto_evpn_support: None,
                auto_flood_reflection_support: None,
            },
            link_capabilities: None,
            holdtime: DEFAULT_LIE_HOLDTIME,
            label: None,
            not_a_ztp_offer: None,
            you_are_flood_repeater: None,
            you_are_sending_too_quickly: None,
            instance_name: None,
            fabric_id: None,
            auto_evpn_version: None,
            auto_flood_reflection_version: None,
            auto_flood_reflection_cluster_id: None,
        };

        let packet = ProtocolPacket {
            header,
            content: encoding::PacketContent::Lie(lie_packet),
        };

        socket.send_packet(&packet)?;
        Ok(())
    }

    // implements the "CLEANUP" procedure
    // CLEANUP: neighbor MUST be reset to unknown
    fn cleanup(&mut self) {
        self.neighbor = None;
    }

    // implements the "PUSH Event" procedure.
    // PUSH Event: queues an event to be executed by the FSM upon exit of this action
    // Note that this adds events to the `chained_event_queue`. When processing an external event,
    // any chained events will also be processed before the next external event. This is to prevent
    // weird edge cases where an external event may be added between a set of chained events.
    fn push(&mut self, event: LieEvent) {
        tracing::trace!(
            event = event.name(),
            external_queue =? self.external_event_queue,
            chained_queue =? self.chained_event_queue,
            "PUSH procedure"
        );
        self.chained_event_queue.push_back(event)
    }

    // implements "update level with event value" from spec
    fn update_level(&mut self, new_level: Level) {
        self.level = new_level;
    }

    // implements "store new HAL" from spec
    fn store_hal(&mut self, new_hal: Level) {
        self.highest_available_level = new_hal;
    }

    // implements "store HAT" from spec
    fn store_hat(&mut self, new_hat: Level) {
        self.highest_adjacency_threeway = new_hat;
    }

    // implements "store HALS" from spec
    fn store_hals(&mut self, new_hals: HALS) {
        self.highest_available_level_systems = new_hals;
    }

    // implements "start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`"
    fn start_multiple_neighbors_timer(&mut self) {
        self.multiple_neighbors_timer.start()
    }

    // implements "update `you_are_flood_repeater` LIE elements based on flood leader election results"
    fn update_you_are_flood_repeater(&mut self) {
        todo!()
    }

    // returns true if "if last valid LIE was received more than `holdtime` ago as advertised by neighbor"
    fn is_lie_expired(&self) -> bool {
        match &self.last_valid_lie {
            Some((timer, _, _)) => timer.is_expired(),
            None => true, // No prior valid LIE to compare against, so always considere expired
        }
    }

    // Send an offer to the ZTP FSM. Specifically, it sends the offer using values from the most
    // recently recieved valid LIE packet. Note that this is _not_ affected by HoldtimeExpired events
    // or the CLEANUP procedure.
    fn send_offer(&self, ztp_fsm: &mut ZtpStateMachine) {
        if let Some((_, header, _)) = &self.last_valid_lie {
            let level = if let Some(level) = header.level {
                Level::Value(level as u8)
            } else {
                Level::Undefined
            };
            let offer = Offer {
                level,
                system_id: header.sender,
                state: self.lie_state,
                expired: false,
            };

            tracing::trace!(offer =? offer, "Sending offer to ZTP FSM");
            ztp_fsm.push_external_event(ZtpEvent::NeighborOffer(offer))
        } else {
            tracing::trace!("Ignoring send_offer call (last_valid_lie is None)");
        }
    }

    /// Expire this link's ZTP offer.
    fn expire_offer(ztp_fsm: &mut ZtpStateMachine, system_id: SystemID) {
        ztp_fsm.expire_offer_by_id(system_id);
    }
}

#[derive(Debug, Serialize)]
struct Neighbor {
    level: Level,
    address: IpAddr,
    system_id: SystemIDType,
    flood_port: UDPPortType,
    name: Option<String>,
    local_link_id: LinkIDType,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize)]
pub enum LieState {
    OneWay,
    TwoWay,
    ThreeWay,
    MultipleNeighborsWait,
}

#[derive(Debug, Clone)]
pub enum LieEvent {
    /// One second timer tick, i.e. the event is generated for FSM by some external entity once a
    /// second. To be quietly ignored if transition does not exist.
    TimerTick,
    /// Node's level has been changed by ZTP or configuration. This is provided by the ZTP FSM.
    LevelChanged(Level),
    /// Best HAL computed by ZTP has changed. This is provided by the ZTP FSM.
    HALChanged(Level),
    /// HAT computed by ZTP has changed. This is provided by the ZTP FSM.
    HATChanged(Level),
    /// Set of HAL offering systems computed by ZTP has changed. This is provided by the ZTP FSM.
    HALSChanged(HALS),
    /// Received LIE on the interface.
    LieRcvd(IpAddr, encoding::PacketHeader, encoding::LIEPacket),
    /// New neighbor seen on the received LIE.
    NewNeighbor,
    /// Received reflection of this node from neighbor, i.e. `neighbor` element in `LiePacket`
    /// corresponds to this node.
    ValidReflection,
    /// Lost previously seen reflection from neighbor, i.e. `neighbor` element in `LiePacket` does
    /// not correspond to this node or is not present.
    NeighborDroppedReflection,
    /// Neighbor changed advertised level from the previously seen one.
    NeighborChangedLevel,
    /// Neighbor changed IP address, i.e. LIE has been received from an address different from
    /// previous LIEs. Those changes will influence the sockets used to listen to TIEs, TIREs, TIDEs.
    NeighborChangedAddress,
    /// Unacceptable header seen.
    UnacceptableHeader,
    /// MTU mismatched.
    MTUMismatch,
    /// Minor fields changed in neighbor's LIE.
    NeighborChangedMinorFields,
    /// Adjacency holddown timer expired.
    HoldtimeExpired,
    /// More than one neighbor seen on interface
    MultipleNeighbors,
    /// Multiple neighbors timer expired.
    MultipleNeighborsDone,
    /// Node's election algorithm determined new set of flood leaders.
    FloodLeadersChanged,
    /// Send a LIE out.
    SendLie,
    /// Update this node's ZTP offer. This is sent to the ZTP FSM.
    UpdateZTPOffer,
}

impl LieEvent {
    fn name(&self) -> &str {
        match self {
            LieEvent::TimerTick => "TimerTick",
            LieEvent::LevelChanged(..) => "LevelChanged",
            LieEvent::HALChanged(..) => "HALChanged",
            LieEvent::HATChanged(..) => "HATChanged",
            LieEvent::HALSChanged(..) => "HALSChanged",
            LieEvent::LieRcvd(..) => "LieRcvd",
            LieEvent::NewNeighbor => "NewNeighbor",
            LieEvent::ValidReflection => "ValidReflection",
            LieEvent::NeighborDroppedReflection => "NeighborDroppedReflection",
            LieEvent::NeighborChangedLevel => "NeighborChangedLevel",
            LieEvent::NeighborChangedAddress => "NeighborChangedAddress",
            LieEvent::UnacceptableHeader => "UnacceptableHeader",
            LieEvent::MTUMismatch => "MTUMismatch",
            LieEvent::NeighborChangedMinorFields => "NeighborChangedMinorFields",
            LieEvent::HoldtimeExpired => "HoldtimeExpired",
            LieEvent::MultipleNeighbors => "MultipleNeighbors",
            LieEvent::MultipleNeighborsDone => "MultipleNeighborsDone",
            LieEvent::FloodLeadersChanged => "FloodLeadersChanged",
            LieEvent::SendLie => "SendLie",
            LieEvent::UpdateZTPOffer => "UpdateZTPOffer",
        }
    }
}

/// A numerical level. A level of "Undefined" typically means that the level was either not specified
/// (and hence will be inferred by ZTP) or it is not known yet. See also: [topology::Level]
// TODO: are levels only in 0-24 range? if so, maybe enforce this?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(untagged)]
pub enum Level {
    Undefined,
    Value(u8),
}

impl From<Option<common::LevelType>> for Level {
    fn from(value: Option<common::LevelType>) -> Self {
        match value {
            Some(level) => Level::Value(level as u8),
            None => Level::Undefined,
        }
    }
}

impl From<Level> for Option<common::LevelType> {
    fn from(value: Level) -> Self {
        match value {
            Level::Undefined => None,
            Level::Value(value) => Some(value as common::LevelType),
        }
    }
}

// TODO: I have no idea what this will consist of.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HALS;

#[derive(Serialize)]
pub struct ZtpStateMachine {
    state: ZtpState,
    #[serde(skip)]
    external_event_queue: VecDeque<ZtpEvent>,
    #[serde(skip)]
    chained_event_queue: VecDeque<ZtpEvent>,
    configured_level: Level,
    leaf_flags: LeafFlags,
    offers: HashMap<SystemIDType, Offer>,
    #[serde(skip)]
    holddown_timer: Timer,
    highest_available_level: Level,
    highest_adjacency_threeway: Level,
    hal_needs_resend: bool,
    hals_needs_resend: bool,
    hat_needs_resend: bool,
    // TODO: this is sort of a hack so that COMPARE_OFFERS and COMPUTE_LEVEL don't both need to
    // do the same work.
    compare_offer_results: CompareOffersResults,
}

impl ZtpStateMachine {
    pub fn new(configured_level: Level, leaf_flags: LeafFlags) -> ZtpStateMachine {
        ZtpStateMachine {
            state: ZtpState::ComputeBestOffer,
            external_event_queue: VecDeque::new(),
            chained_event_queue: VecDeque::new(),
            configured_level,
            leaf_flags,
            offers: HashMap::new(),
            holddown_timer: Timer::new(Duration::from_secs(DEFAULT_ZTP_HOLDTIME as u64)),
            highest_available_level: Level::Undefined,
            highest_adjacency_threeway: Level::Undefined,
            hal_needs_resend: false,
            hals_needs_resend: false,
            hat_needs_resend: false,
            compare_offer_results: CompareOffersResults {
                hal: None,
                hat: None,
            },
        }
    }

    /// Process all external events, if there exist any events in the event queue. Note that this
    /// also processes any events pushed by the PUSH procedure, so the `chained_event_queue` will
    /// be empty both before and after this call. This function returns a vector containing events
    /// that should be pushed to the LIE FSMs associated with this state machine. In particular, the
    /// following events may be returned:
    /// LieEvent::HALChanged
    /// LieEvent::HATChanged
    /// LieEvent::HALSChanged
    pub fn process_external_events(&mut self) -> Vec<LieEvent> {
        assert!(self.chained_event_queue.is_empty());
        let mut lie_events = vec![];
        while !self.external_event_queue.is_empty() {
            let events = self.process_external_event();
            lie_events.extend(events);
        }
        assert!(self.chained_event_queue.is_empty());
        lie_events
    }

    /// Process a single external event, if there exists an event in the event queue. Note that this
    /// also processes any events pushed by the PUSH procedure, so the `chained_event_queue` will
    /// be empty both before and after this call.
    fn process_external_event(&mut self) -> Vec<LieEvent> {
        assert!(self.chained_event_queue.is_empty());
        let mut lie_events = vec![];

        if let Some(event) = self.external_event_queue.pop_front() {
            let _span = tracing::trace_span!(
                target: "ZTP_FSM",
                "process_external_event",
                queue_type = "external",
                event = event.name(),
                state =? self.state
            )
            .entered();
            let new_state = self.process_ztp_event(event);
            let events = self.transition_to(new_state);
            lie_events.extend(events);
        }

        // Drain the chained event queue, if an external event caused some events to be pushed.
        while let Some(event) = self.chained_event_queue.pop_front() {
            let _span = tracing::trace_span!(
                target: "ZTP_FSM",
                "process_external_event",
                queue_type = "chained",
                event = event.name(),
                state =? self.state
            )
            .entered();
            let new_state = self.process_ztp_event(event);
            let events = self.transition_to(new_state);
            lie_events.extend(events);
        }
        lie_events
    }

    /// Set the current state to the new state. If this would cause the state to enter LieState::OneWay,
    /// then CLEANUP is also performed. If the current state is already equal to the new state, noop.
    fn transition_to(&mut self, new_state: ZtpState) -> Vec<LieEvent> {
        let mut events = vec![];
        if new_state != self.state {
            tracing::trace!(from =? self.state, to=? new_state, "transitioning");
            if new_state == ZtpState::ComputeBestOffer {
                // on Entry into ComputeBestOffer: LEVEL_COMPUTE
                self.level_compute();
            } else if new_state == ZtpState::UpdatingClients {
                // on Entry into UpdatingClients: update all LIE FSMs with computation results
                // here we sent events, which will be returned and eventually added to all LIE FSMs.
                if self.hal_needs_resend {
                    events.push(LieEvent::HALChanged(self.highest_available_level));
                    if let Level::Value(_) = self.highest_available_level {
                        // TODO: rift-python just directly sets self._derived_level, which means they
                        // don't issue LevelChanged (which also means that the LIE FSM does not
                        // reset to OneWay)
                        tracing::debug!(
                            new_level =? self.level(),
                            "Pushing LevelChanged from ZTP FSM"
                        );
                        events.push(LieEvent::LevelChanged(self.level()));
                    }

                    self.hal_needs_resend = false;
                }
                if self.hat_needs_resend {
                    events.push(LieEvent::HATChanged(self.highest_adjacency_threeway));
                    self.hat_needs_resend = false;
                }
                if self.hals_needs_resend {
                    // TODO: What should a HALS actually look like?
                    events.push(LieEvent::HALSChanged(HALS));
                    self.hals_needs_resend = false;
                }
            }
            self.state = new_state;
        }
        events
    }

    /// Push an external event onto the ZTPEvent queue.
    pub fn push_external_event(&mut self, event: ZtpEvent) {
        tracing::trace!(event = event.name(), "pushing external event");
        self.external_event_queue.push_back(event);
    }

    fn process_ztp_event(&mut self, event: ZtpEvent) -> ZtpState {
        match self.state {
            ZtpState::ComputeBestOffer => match event {
                ZtpEvent::ChangeLocalConfiguredLevel(new_level) => {
                    // store configured level
                    self.store_configured_level(new_level);
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::BetterHAT => ZtpState::HoldingDown,
                ZtpEvent::ShortTic => {
                    // remove expired offers and if holddown timer expired PUSH_EVENT HoldDownExpired
                    self.remove_expired_offers();
                    if self.holddown_timer.is_expired() {
                        self.push(ZtpEvent::HoldDownExpired);
                    }
                    ZtpState::HoldingDown
                }
                ZtpEvent::NeighborOffer(offer) => {
                    // PROCESS_OFFER
                    self.process_offer(offer);
                    ZtpState::HoldingDown
                }
                ZtpEvent::ComputationDone => ZtpState::HoldingDown,
                ZtpEvent::BetterHAL => ZtpState::HoldingDown,
                ZtpEvent::LostHAT => ZtpState::HoldingDown,
                ZtpEvent::LostHAL => ZtpState::HoldingDown,
                ZtpEvent::HoldDownExpired => {
                    // PURGE_OFFERS
                    self.purge_offers();
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::ChangeLocalHierarchyIndications(new_flags) => {
                    // store leaf flags
                    self.store_leaf_flags(new_flags);
                    ZtpState::ComputeBestOffer
                }
            },
            ZtpState::HoldingDown => match event {
                ZtpEvent::LostHAT => {
                    self.level_compute(); // LEVEL_COMPUTE
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::NeighborOffer(offer) => {
                    self.process_offer(offer); // PROCESS_OFFER
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::BetterHAT => {
                    self.level_compute(); // LEVEL_COMPUTE
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::ChangeLocalHierarchyIndications(new_flags) => {
                    // store leaf flags and LEVEL_COMPUTE
                    self.store_leaf_flags(new_flags);
                    self.level_compute();
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::LostHAL => {
                    // if any southbound adjacencies present then update holddown timer
                    // to normal duration else fire holddown timer immediately
                    self.check_sounthbound_adjacencies();
                    ZtpState::HoldingDown
                }
                ZtpEvent::ShortTic => {
                    self.remove_expired_offers(); // remove expired offers
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::ComputationDone => ZtpState::UpdatingClients,
                ZtpEvent::ChangeLocalConfiguredLevel(new_level) => {
                    // store configured level and LEVEL_COMPUTE
                    self.store_configured_level(new_level);
                    self.level_compute();
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::BetterHAL => {
                    self.level_compute(); // LEVEL_COMPUTE
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::HoldDownExpired => {
                    unreachable!("event {} cannot occur in {:?}", event.name(), self.state)
                }
            },
            ZtpState::UpdatingClients => match event {
                ZtpEvent::ShortTic => {
                    self.remove_expired_offers(); // remove expired offers
                    ZtpState::UpdatingClients
                }
                ZtpEvent::LostHAL => {
                    // if any southbound adjacencies present then update holddown timer
                    // to normal duration else fire holddown timer immediately
                    self.check_sounthbound_adjacencies();
                    ZtpState::HoldingDown
                }
                ZtpEvent::BetterHAT => ZtpState::ComputeBestOffer,
                ZtpEvent::BetterHAL => ZtpState::ComputeBestOffer,
                ZtpEvent::ChangeLocalConfiguredLevel(new_level) => {
                    self.store_configured_level(new_level); // store configured level
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::ChangeLocalHierarchyIndications(new_flags) => {
                    self.store_leaf_flags(new_flags); // store leaf flags
                    ZtpState::ComputeBestOffer
                }
                ZtpEvent::NeighborOffer(offer) => {
                    self.process_offer(offer); // PROCESS_OFFER
                    ZtpState::UpdatingClients
                }
                ZtpEvent::LostHAT => ZtpState::ComputeBestOffer,
                ZtpEvent::ComputationDone => {
                    unreachable!("event {} cannot occur in {:?}", event.name(), self.state)
                }
                ZtpEvent::HoldDownExpired => {
                    unreachable!("event {} cannot occur in {:?}", event.name(), self.state)
                }
            },
        }
    }

    // implements the "PUSH Event" procedure.
    // PUSH Event: queues an event to be executed by the FSM upon exit of this action
    // Note that this adds events to the `chained_event_queue`. When processing an external event,
    // any chained events will also be processed before the next external event. This is to prevent
    // weird edge cases where an external event may be added between a set of chained events.
    fn push(&mut self, event: ZtpEvent) {
        tracing::trace!(event = event.name(), "PUSH procedure");
        self.chained_event_queue.push_back(event);
    }

    // Implements the COMPARE_OFFERS procedure:
    // checks whether based on current offers and held last results the events
    // BetterHAL/LostHAL/BetterHAT/LostHAT are necessary and returns them
    fn compare_offers(&mut self) -> Vec<ZtpEvent> {
        let mut events = vec![];

        let best_offer = self.offers.values().map(|x| x.level).max();
        let best_offer_hat = self
            .offers
            .values()
            .filter_map(|x| {
                if x.state == LieState::ThreeWay {
                    Some(x.level)
                } else {
                    None
                }
            })
            .max();

        if let Some(hal) = best_offer && self.highest_available_level != hal{
            events.push(ZtpEvent::BetterHAL);
        } else {
            events.push(ZtpEvent::LostHAL);
        }

        if let Some(hat) = best_offer_hat && self.highest_adjacency_threeway != hat{
            events.push(ZtpEvent::BetterHAT);
        } else {
            events.push(ZtpEvent::LostHAT);
        }

        self.compare_offer_results = CompareOffersResults {
            hal: best_offer,
            hat: best_offer_hat,
        };

        events
    }

    // Implements the UPDATE_OFFER procedure:
    // store current offer with adjacency holdtime as lifetime and COMPARE_OFFERS,
    // then PUSH according events
    // TODO: what does "adjacency holdtime" mean?
    fn update_offer(&mut self, offer: Offer) {
        tracing::trace!(offer =? offer, "UPDATE_OFFER procedure");
        self.offers.insert(offer.system_id, offer);

        for event in self.compare_offers() {
            self.push(event);
        }
    }

    // Implements the LEVEL_COMPUTE procedure:
    // compute best offered or configured level and HAL/HAT, if anything changed PUSH ComputationDone
    fn level_compute(&mut self) {
        tracing::trace!("LEVEL_COMPUTE procedure");

        let mut anything_changed = false;
        let new_hal = self.compare_offer_results.hal;
        let new_hat = self.compare_offer_results.hat;

        if let Some(new_hal) = new_hal && new_hal != self.highest_available_level {
            self.highest_available_level = new_hal;
            self.hal_needs_resend = true;
            anything_changed = true;
        }

        if let Some(new_hat) = new_hat && new_hat != self.highest_adjacency_threeway {
            self.highest_adjacency_threeway = new_hat;
            self.hat_needs_resend = true;
            anything_changed = true;
        }

        // rift-python appears to push this unconditionally?
        if anything_changed {
            self.push(ZtpEvent::ComputationDone);
        }
    }

    // Implements the REMOVE_OFFER procedure:
    // remote the according offer and COMPARE_OFFERS, PUSH according events
    fn remove_offer(&mut self, offer: &Offer) {
        let removed = self.offers.remove(&offer.system_id);
        if removed.is_some() {
            tracing::trace!(offer =? offer, remaining_offers =? self.offers, "REMOVE_OFFER procedure - removed offer");
        } else {
            tracing::trace!(offer =? offer, remaining_offers =? self.offers, "REMOVE_OFFER procedure - offer not found");
        }

        for event in self.compare_offers() {
            self.push(event);
        }
    }

    // Implements the PURGE_OFFERS procedure:
    // REMOVE_OFFER for all held offers, COMPARE_OFFERS, PUSH according events
    fn purge_offers(&mut self) {
        // I think the spec is wrong here.
        // Spec should be "remove all held offers", not "REMOVE_OFFER for all held offers"
        self.offers.clear();

        for event in self.compare_offers() {
            self.push(event);
        }
    }

    // Implements the PROCESS_OFFER procedure:
    // 1. if no level offered then REMOVE_OFFER
    // 2. else
    //    1. if offered level > leaf then UPDATE_OFFER
    //    2. else REMOVE_OFFER
    fn process_offer(&mut self, offer: Offer) {
        let _span = tracing::trace_span!("PROCESS_OFFER procedure", offer =? offer).entered();
        match offer.level {
            Level::Undefined => self.remove_offer(&offer),
            Level::Value(level) => {
                if level > LEAF_LEVEL {
                    self.update_offer(offer);
                } else {
                    self.remove_offer(&offer);
                }
            }
        }
    }

    // implements "store leaf flags"
    fn store_leaf_flags(&mut self, new_flags: LeafFlags) {
        self.leaf_flags = new_flags;
    }

    // implements "store configured level"
    fn store_configured_level(&mut self, new_level: Level) {
        self.configured_level = new_level;
    }

    // implements "remove expired offers"
    fn remove_expired_offers(&mut self) {
        self.offers.retain(|_, offer| !offer.expired);
    }

    // implements "if any southbound adjacencies present then update holddown timer
    // to normal duration else fire holddown timer immediately"
    fn check_sounthbound_adjacencies(&mut self) {
        let any_southbound = self.offers.values().any(|offer| offer.level < self.level());
        if any_southbound {
            // Set holddown timer to normal duration.
            self.holddown_timer.start();
        } else {
            // Fire the holddown timer immediately.
            self.holddown_timer.force_expire();
        }
    }

    // Attempt to expire an offer by the given system ID. Returns false if the ID is not there or if
    // the offer is already expired, and true otherwise.
    pub fn expire_offer_by_id(&mut self, system_id: SystemID) -> bool {
        match self.offers.get_mut(&system_id.get()) {
            Some(offer) => {
                offer.expired = true;
                true
            }
            None => false,
        }
    }

    fn derived_level(&self) -> Level {
        match self.highest_available_level {
            Level::Undefined => Level::Undefined,
            Level::Value(value) => Level::Value(value.saturating_sub(1)),
        }
    }

    fn level(&self) -> Level {
        if self.configured_level == Level::Undefined {
            self.derived_level()
        } else {
            self.configured_level
        }
    }
}

#[derive(Serialize)]
struct CompareOffersResults {
    hal: Option<Level>,
    hat: Option<Level>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum ZtpState {
    ComputeBestOffer,
    HoldingDown,
    UpdatingClients,
}

#[derive(Debug, Clone)]
pub enum ZtpEvent {
    // node locally configured with new leaf flags.
    ChangeLocalHierarchyIndications(LeafFlags),
    // node locally configured with a defined level
    ChangeLocalConfiguredLevel(Level),
    // a new neighbor offer with optional level and neighbor state.
    NeighborOffer(Offer),
    // better HAL computed internally.
    BetterHAL,
    // better HAT computed internally.
    BetterHAT,
    // lost last HAL in computation.
    LostHAL,
    // lost HAT in computation.
    LostHAT,
    // computation performed.
    ComputationDone,
    // holddown timer expired.
    HoldDownExpired,
    // one second timer tic, i.e. the event is generated for FSM by some external entity once a second.
    // To be ignored if transition does not exist.
    ShortTic,
}

impl ZtpEvent {
    fn name(&self) -> &str {
        match self {
            ZtpEvent::ChangeLocalHierarchyIndications(_) => "ChangeLocalHierarchyIndications",
            ZtpEvent::ChangeLocalConfiguredLevel(_) => "ChangeLocalConfiguredLevel",
            ZtpEvent::NeighborOffer(_) => "NeighborOffer",
            ZtpEvent::BetterHAL => "BetterHAL",
            ZtpEvent::BetterHAT => "BetterHAT",
            ZtpEvent::LostHAL => "LostHAL",
            ZtpEvent::LostHAT => "LostHAT",
            ZtpEvent::ComputationDone => "ComputationDone",
            ZtpEvent::HoldDownExpired => "HoldDownExpired",
            ZtpEvent::ShortTic => "ShortTic",
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct Offer {
    level: Level,
    system_id: SystemIDType,
    state: LieState,
    expired: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeafFlags;

pub struct Timer {
    start: Option<Instant>,
    length: Duration,
}

impl Timer {
    pub fn new(length: Duration) -> Timer {
        Timer {
            start: None,
            length,
        }
    }

    /// Start the timer. If the timer is already running, this function resets the timer.
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    /// Force the timer to expire, even if the timer still has some time left on it.
    pub fn force_expire(&mut self) {
        self.start = None;
    }

    /// Returns true if the timer has been running for longer than `duration` or if the timer
    /// has not been started yet.
    pub fn is_expired(&self) -> bool {
        match self.start {
            Some(start) => start.elapsed() > self.length,
            None => true,
        }
    }
}
