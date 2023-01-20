use std::{collections::VecDeque, io, net::IpAddr};

use crate::{
    models::{
        common::{
            self, LinkIDType, MTUSizeType, SystemIDType, UDPPortType, DEFAULT_BANDWIDTH,
            DEFAULT_LIE_HOLDTIME, ILLEGAL_SYSTEM_I_D, LEAF_LEVEL,
        },
        encoding::{
            self, LIEPacket, PacketHeader, ProtocolPacket, PROTOCOL_MAJOR_VERSION,
            PROTOCOL_MINOR_VERSION,
        },
    },
    network::{LinkSocket, NodeInfo},
    topology::SystemID,
};

/// The state machien for LIE exchange.
pub struct LieStateMachine {
    /// Determines if a link is logically present in the topology. If the LIEState is ThreeWay, then
    /// the link is logically present. Otherwise, it is not.
    lie_state: LieState,
    external_event_queue: VecDeque<LieEvent>,
    chained_event_queue: VecDeque<LieEvent>,
    /// This node's level, as computed by the ZTP/LIE FSMs.
    derived_level: Level,
    /// from spec:  Set of nodes offering HAL VOLs
    highest_available_level_systems: HALS,
    // from spec: Highest defined level value seen from all VOLs received.
    highest_available_level: Level,
    /// from spec: Highest neighbor level of all the formed ThreeWay adjacencies for the node.
    highest_adjacency_threeway: Level,
    /// The neighbor value, which is set by PROCESS_LIE and checked by SEND_LIE. If this value is
    /// Some, then a neighbor has been observed and will be sent out during SEND_LIE to reflect back
    /// to the node on the other end of the Link.
    neighbor: Option<Neighbor>,
    /// The ZTP state machine. Maybe this should go into the Link?
    ztp_fsm: ZtpStateMachine,
}

impl LieStateMachine {
    pub fn new(configured_level: Level) -> LieStateMachine {
        LieStateMachine {
            lie_state: LieState::OneWay,
            external_event_queue: VecDeque::new(),
            chained_event_queue: VecDeque::new(),
            derived_level: configured_level,
            highest_available_level_systems: HALS,
            highest_available_level: Level::Undefined,
            highest_adjacency_threeway: Level::Undefined,
            neighbor: None,
            ztp_fsm: ZtpStateMachine,
        }
    }

    /// Process a single external event, if there exists events in the event queue. Note that this
    /// also processes any events pushed by the PUSH procedure, so the `chained_event_queue` will
    /// be empty both before and after this call.
    pub fn process_external_event(
        &mut self,
        socket: &mut LinkSocket,
        node_info: &NodeInfo,
    ) -> io::Result<()> {
        assert!(self.chained_event_queue.is_empty());
        if let Some(event) = self.external_event_queue.pop_front() {
            println!(
                "processing external event: {} (in {:?})",
                event.name(),
                self.lie_state
            );
            let new_state = self.process_lie_event(event, socket, node_info)?;
            if new_state != self.lie_state {
                println!("transitioning: {:?} -> {:?}", self.lie_state, new_state);
                self.lie_state = new_state;
            }
        }

        // Drain the chained event queue, if an external event caused some events to be pushed.
        while let Some(event) = self.chained_event_queue.pop_front() {
            println!(
                "processing chained event: {} (in {:?})",
                event.name(),
                self.lie_state
            );
            let new_state = self.process_lie_event(event, socket, node_info)?;
            if new_state != self.lie_state {
                println!("transitioning: {:?} -> {:?}", self.lie_state, new_state);
                self.lie_state = new_state;
            }
        }
        Ok(())
    }

    /// Push an external event onto the LIEEvent queue.
    pub fn push_external_event(&mut self, event: LieEvent) {
        println!("Pushing external event {}", event.name());
        self.external_event_queue.push_back(event);
    }

    // process the given LIE event. The return value is the LieState to transition into next.
    fn process_lie_event(
        &mut self,
        event: LieEvent,
        socket: &mut LinkSocket,
        node_info: &NodeInfo,
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
                LieEvent::HoldtimeExpired => LieState::OneWay,
                LieEvent::HALSChanged(new_hals) => {
                    self.store_HALS(new_hals); // store HALS
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
                    self.ztp_fsm.send_ztp_offer();
                    LieState::OneWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_HAT(new_hat); // store HAT
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
                    self.store_HAL(new_hal); // store new HAL
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
                    self.ztp_fsm.send_ztp_offer(); // send offer to ZTP FSM
                    LieState::TwoWay
                }
                LieEvent::HoldtimeExpired => LieState::OneWay,
                LieEvent::MTUMismatch => LieState::OneWay,
                LieEvent::UnacceptableHeader => LieState::OneWay,
                LieEvent::ValidReflection => LieState::ThreeWay,
                LieEvent::SendLie => {
                    self.send_lie_procedure(socket, node_info)?; // SEND_LIE
                    LieState::TwoWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_HAT(new_hat); // store HAT
                    LieState::TwoWay
                }
                LieEvent::HALChanged(new_hal) => {
                    self.store_HAL(new_hal); // store new HAL
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
                    todo!();
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
                    self.store_HALS(new_hals); // store HALS
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
                LieEvent::HoldtimeExpired => LieState::OneWay,
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
                    self.derived_level = new_level; // update level with event value
                    LieState::OneWay
                }
                LieEvent::HALSChanged(new_hals) => {
                    self.highest_available_level_systems = new_hals;
                    LieState::ThreeWay
                }
                LieEvent::TimerTick => {
                    // PUSH SendLie event, if last valid LIE was received more than `holdtime` ago as advertised by neighbor then PUSH HoldtimeExpired event
                    todo!();
                    LieState::ThreeWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.store_HAT(new_hat); // store HAT
                    LieState::ThreeWay
                }
                LieEvent::UpdateZTPOffer => {
                    self.ztp_fsm.send_ztp_offer(); // send offer to ZTP FSM
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
                LieEvent::HoldtimeExpired => LieState::MultipleNeighborsWait,
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
                    self.ztp_fsm.send_ztp_offer(); // send offer to ZTP FSM
                    LieState::MultipleNeighborsWait
                }
                LieEvent::MultipleNeighborsDone => LieState::OneWay,
                LieEvent::HATChanged(new_hat) => {
                    self.store_HAT(new_hat); // store HAT
                    LieState::MultipleNeighborsWait
                }
                LieEvent::NeighborChangedAddress => LieState::MultipleNeighborsWait,
                LieEvent::HALSChanged(new_hals) => {
                    self.store_HALS(new_hals); // store HALS
                    LieState::MultipleNeighborsWait
                }
                LieEvent::HALChanged(new_hal) => {
                    self.store_HAL(new_hal); // store new HAL
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
                    todo!();
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
        address: IpAddr,
        lie_header: &PacketHeader,
        lie_packet: &LIEPacket,
        system_id: SystemID,
        local_link_id: LinkIDType,
        mtu: MTUSizeType,
    ) {
        println!("\tPROCESS_LIE");
        let lie_level: Level = lie_header.level.into();

        // 1. if LIE has major version not equal to this node's *or*
        //       system ID equal to this node's system IDor `IllegalSystemID`
        //    then CLEANUP
        if lie_header.major_version != PROTOCOL_MAJOR_VERSION
            || lie_header.sender == system_id.get()
            || lie_header.sender == ILLEGAL_SYSTEM_I_D
        {
            self.cleanup();
            return;
        }

        if lie_packet.link_mtu_size != Some(mtu) {
            // 2. if LIE has non matching MTUs
            //    then CLEANUP, PUSH UpdateZTPOffer, PUSH MTUMismatch
            self.cleanup();
            self.push(LieEvent::UpdateZTPOffer);
            self.push(LieEvent::MTUMismatch);
            return;
        }

        // 3. if LIE has undefined level OR
        //       this node's level is undefined OR
        //       this node is a leaf and remote level is lower than HAT OR
        //       (LIE's level is not leaf AND its difference is more than one from this node's level)
        //    then CLEANUP, PUSH UpdateZTPOffer, PUSH UnacceptableHeader
        let unacceptable_header = match (self.derived_level, lie_level) {
            (_, Level::Undefined) => true,
            (Level::Undefined, _) => true,
            (Level::Value(derived_level), Level::Value(lie_level)) => {
                let this_node_is_leaf = derived_level == LEAF_LEVEL as u8;
                let remote_lower_than_hat = match self.highest_adjacency_threeway {
                    // TODO: if our HAT is undefined, do we treat that always "lower" than the remote's level? (aka: always true)
                    // or not (always false)?
                    Level::Undefined => true,
                    Level::Value(hat) => lie_level < hat,
                };

                let lie_is_not_leaf = lie_level != LEAF_LEVEL as u8;
                let lie_more_than_one_away = u8::abs_diff(lie_level, derived_level) > 1;
                (this_node_is_leaf && remote_lower_than_hat)
                    || (lie_is_not_leaf && lie_more_than_one_away)
            }
        };
        if unacceptable_header {
            self.cleanup();
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
        system_id: SystemID,
        local_link_id: LinkIDType,
    ) {
        match (dbg!(self.lie_state), dbg!(&packet.neighbor)) {
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
                originator: node_info.system_id.get(),
                remote_id: neighbor.local_link_id, // TODO: should this be the system id?
            }),
            None => None,
        };

        let header = PacketHeader {
            major_version: PROTOCOL_MAJOR_VERSION,
            minor_version: PROTOCOL_MINOR_VERSION,
            sender: node_info.system_id.get(),
            level: self.derived_level.into(),
        };

        // TODO: fill in these values with real data, instead of None
        let lie_packet = LIEPacket {
            name: node_info.node_name.clone(),
            local_id: socket.local_link_id as common::LinkIDType,
            flood_port: socket.flood_port() as common::UDPPortType,
            link_mtu_size: Some(socket.mtu),
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
        self.neighbor = None
    }

    // implements the "PUSH Event" procedure.
    // PUSH Event: queues an event to be executed by the FSM upon exit of this action
    // Note that this adds events to the `chained_event_queue`. When processing an external event,
    // any chained events will also be processed before the next external event. This is to prevent
    // weird edge cases where an external event may be added between a set of chained events.
    fn push(&mut self, event: LieEvent) {
        println!("\tPUSH {:?}", event);
        self.chained_event_queue.push_back(event)
    }

    // implements "update level with event value" from spec
    fn update_level(&mut self, new_level: Level) {
        self.derived_level = new_level;
    }

    // implements "store new HAL" from spec
    fn store_HAL(&mut self, new_hal: Level) {
        self.highest_available_level = new_hal;
    }

    // implements "store HAT" from spec
    fn store_HAT(&mut self, new_hat: Level) {
        self.highest_adjacency_threeway = new_hat;
    }

    // implements "store HALS" from spec
    fn store_HALS(&mut self, new_hals: HALS) {
        self.highest_available_level_systems = new_hals;
    }

    // implements "start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`"
    fn start_multiple_neighbors_timer(&mut self) {
        todo!()
    }

    // implements "update `you_are_flood_repeater` LIE elements based on flood leader election results"
    fn update_you_are_flood_repeater(&mut self) {
        todo!()
    }
}

struct Neighbor {
    level: Level,
    address: IpAddr,
    system_id: SystemIDType,
    flood_port: UDPPortType,
    name: Option<String>,
    local_link_id: LinkIDType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy)]
pub struct HALS;

struct ZtpStateMachine;

impl ZtpStateMachine {
    fn send_ztp_offer(&self) {
        println!("TODO: send_ztp_offer");
    }
}

#[cfg(test)]
mod test {

    #[test]
    #[ignore = "not yet implemented"]
    fn two_nodes() {
        // let id_a = 0;
        // let id_b = 1;
        // let mut top_of_fabric = Node::new(Some(TOP_OF_FABRIC_LEVEL), id_a);
        // let mut leaf_node = Node::new(None, id_b);
        // top_of_fabric.add_link(&leaf_node);
        // leaf_node.add_link(&top_of_fabric);

        // let mut network = Network {
        //     nodes: vec![top_of_fabric, leaf_node],
        // };
        // network.run();

        // let top_of_fabric = network.get(id_a).unwrap();
        // let leaf_node = network.get(id_b).unwrap();
        // assert_eq!(top_of_fabric.discovered_level, Some(TOP_OF_FABRIC_LEVEL));
        // assert_eq!(leaf_node.discovered_level, Some(LEAF_LEVEL));
    }
}
