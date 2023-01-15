use std::collections::VecDeque;

use crate::models::{
    common::{
        self, LinkIDType, MTUSizeType, SystemIDType, UDPPortType, ILLEGAL_SYSTEM_I_D, LEAF_LEVEL,
    },
    encoding::{self, LIEPacket, PacketHeader, PROTOCOL_MAJOR_VERSION},
};

/// A Link representing a connection from one Node to another Node. Note that these are physical Links
/// (that is to say, they are links which are physical present in the topology, but not nessecarily
/// links which that will be considered to be logically present in the topology later on.)
/// Note that this struct represents only one direction in a link--the other linked Node also has it's
/// own Link pointing back to the first Node.
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
    /// The system ID of this node.
    system_id: SystemIDType,
    /// THe MTU of this node.
    mtu: MTUSizeType,
    neighbor: Option<Neighbor>,
}

impl LieStateMachine {
    pub fn process_next_lie_event(&mut self) {
        // fetch an event out of (one of?) the queues and process it.
        todo!()
    }

    fn process_lie_event(&mut self, event: LieEvent) -> LieState {
        match self.lie_state {
            LieState::OneWay => match event {
                LieEvent::TimerTick => {
                    self.push(LieEvent::SendLie);
                    LieState::OneWay
                }
                LieEvent::UnacceptableHeader => LieState::OneWay,
                LieEvent::LevelChanged(new_level) => {
                    // update level with event value, PUSH SendLie event
                    self.derived_level = new_level;
                    self.push(LieEvent::SendLie);
                    LieState::OneWay
                }
                LieEvent::NeighborChangedMinorFields => LieState::OneWay,
                LieEvent::NeighborChangedLevel => LieState::OneWay,
                LieEvent::NewNeighbor => {
                    self.push(LieEvent::SendLie);
                    LieState::TwoWay
                }
                LieEvent::HoldtimeExpired => LieState::OneWay,
                LieEvent::HALSChanged(new_hals) => {
                    // store HALS
                    self.highest_available_level_systems = new_hals;
                    LieState::OneWay
                }
                LieEvent::NeighborChangedAddress => LieState::OneWay,
                LieEvent::LieRcvd(lie_header, lie_packet) => {
                    // PROCESS_LIE
                    self.process_lie_procedure(&lie_header, &lie_packet);
                    LieState::OneWay
                }
                LieEvent::ValidReflection => LieState::ThreeWay,
                LieEvent::SendLie => {
                    self.send_lie_procedure(); // SEND_LIE
                    LieState::OneWay
                }
                LieEvent::UpdateZTPOffer => {
                    todo!(); // send offer to ZTP FSM
                    LieState::OneWay
                }
                LieEvent::HATChanged(new_hat) => {
                    self.highest_adjacency_threeway = new_hat; // store HAT
                    LieState::OneWay
                }
                LieEvent::MultipleNeighbors => {
                    todo!(); // start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
                    LieState::MultipleNeighborsWait
                }
                LieEvent::MTUMismatch => LieState::OneWay,
                LieEvent::FloodLeadersChanged => {
                    todo!(); // update `you_are_flood_repeater` LIE elements based on flood leader election results
                    LieState::OneWay
                }
                LieEvent::NeighborDroppedReflection => LieState::OneWay,
                LieEvent::HALChanged(new_hal) => {
                    self.highest_available_level = new_hal; // store new HAL
                    LieState::OneWay
                }
                // Illegal State Transitions
                LieEvent::MultipleNeighborsDone => {
                    unreachable!("This event should only occur in MultipleNeighborsWait.")
                }
            },
            LieState::TwoWay => todo!(),
            LieState::ThreeWay => todo!(),
            LieState::MultipleNeighborsWait => todo!(),
        }
    }

    // implements the "PROCESS_LIE" procedure
    pub fn process_lie_procedure(&mut self, lie_header: &PacketHeader, lie_packet: &LIEPacket) {
        let lie_level: Level = lie_header.level.into();

        let pushed_events = if lie_header.major_version != PROTOCOL_MAJOR_VERSION
            || lie_header.sender == self.system_id
            || lie_header.sender == ILLEGAL_SYSTEM_I_D
        {
            // 1. if LIE has major version not equal to this node's *or* system ID equal to this node'ssystem ID or `IllegalSystemID`
            //    then CLEANUP
            self.cleanup();
        } else if lie_packet.link_mtu_size != Some(self.mtu) {
            // 2. if LIE has non matching MTUs
            //    then CLEANUP, PUSH UpdateZTPOffer, PUSH MTUMismatch
            self.cleanup();
            self.push(LieEvent::UpdateZTPOffer);
            self.push(LieEvent::MTUMismatch);
        } else if lie_level.is_undefined()
            || self.derived_level.is_undefined()
            || (self.derived_level.is_leaf() && lie_level < self.highest_available_level)
            || (!lie_level.is_leaf() && lie_level - self.derived_level > 1)
        {
            // 3. if LIE has undefined level OR
            //       this node's level is undefined OR
            //       this node is a leaf and remote level is lower than HAT OR
            //       (LIE's level is not leaf AND its difference is more than one from this node's level)
            //    then CLEANUP, PUSH UpdateZTPOffer, PUSH UnacceptableHeader
            self.cleanup();
            self.push(LieEvent::UpdateZTPOffer);
            self.push(LieEvent::UnacceptableHeader);
        } else {
            // 4. PUSH UpdateZTPOffer, construct temporary new neighbor structure with values from LIE,
            self.push(LieEvent::UpdateZTPOffer);
            let new_neighbor = Neighbor {
                name: lie_packet.name,
                system_id: lie_header.sender,
                local_link_id: lie_packet.local_id,
                level: lie_header.level.into(),
                address: todo!(), // on the udp packet
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
            // 5. CHECK_THREE_WAY (i believe the draft spec here is wrong: This "CHECK_THREE_WAY" should
            // be at the end of step 4.4, not it's own step as step 5.)
            if let Some(curr_neighbor) = self.neighbor {
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
                    self.check_three_way();
                }
            } else {
                // if no current neighbor exists then set neighbor to new neighbor, PUSH NewNeighbor event, CHECK_THREE_WAY
                self.neighbor = Some(new_neighbor);
                self.push(LieEvent::NewNeighbor);
                self.check_three_way();
            }
        };
    }

    // implements the "CHECK_THREE_WAY" procedure
    // CHECK_THREE_WAY: if current state is OneWay do nothing else
    // 1. if LIE packet does not contain neighbor
    //    then if current state is ThreeWay
    //         then PUSH NeighborDroppedReflection else
    // 2. if packet reflects this system's ID and local port and state is ThreeWay
    //    then PUSH event ValidReflection
    //    else PUSH event MultipleNeighbors
    pub fn check_three_way(&self) {
        todo!()
    }

    // implements the "SEND_LIE" procedure.
    // SEND_LIE:
    // 1. create and send a new LIE packet reflecting the neighbor if known and valid and
    // 2. setting the necessary `not_a_ztp_offer` variable if level was derived from last
    //    known neighbor on this interface and
    // 3. setting `you_are_not_flood_repeater` to computed value
    fn send_lie_procedure(&self) {
        todo!()
    }

    // implements the "CLEANUP" procedure
    // CLEANUP: neighbor MUST be reset to unknown
    pub fn cleanup(&mut self) {
        self.neighbor = None
    }

    // implements the "PUSH Event" procedure.
    // PUSH Event: queues an event to be executed by the FSM upon exit of this action
    fn push(&mut self, event: LieEvent) {
        self.chained_event_queue.push_back(event)
    }
}

struct Neighbor {
    level: Level,
    address: (),
    system_id: SystemIDType,
    flood_port: UDPPortType,
    name: Option<String>,
    local_link_id: LinkIDType,
}

#[derive(Debug, Clone, Copy)]
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
    LieRcvd(encoding::PacketHeader, encoding::LIEPacket),
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

// TODO: are levels only in 0-24 range? if so, maybe enforce this?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Undefined,
    Value(u8),
}

impl Level {
    fn is_leaf(&self) -> bool {
        match self {
            Level::Undefined => false,
            Level::Value(value) => *value == LEAF_LEVEL as u8,
        }
    }

    fn is_undefined(&self) -> bool {
        match self {
            Level::Undefined => true,
            Level::Value(_) => false,
        }
    }
}

impl From<Option<common::LevelType>> for Level {
    fn from(value: Option<common::LevelType>) -> Self {
        match value {
            Some(level) => Level::Value(level as u8),
            None => Level::Undefined,
        }
    }
}

// TODO: I have no idea what this will consist of.
#[derive(Debug, Clone, Copy)]
struct HALS;

#[cfg(test)]
mod test {
    use crate::models::common::{LEAF_LEVEL, TOP_OF_FABRIC_LEVEL};

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
