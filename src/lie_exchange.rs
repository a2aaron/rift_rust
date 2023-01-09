use std::{
    collections::VecDeque,
    sync::atomic::{AtomicI64, Ordering},
};

use crate::models::common::{LevelType, SystemIDType};

static ID: AtomicI64 = AtomicI64::new(0);

/// Represents a network of nodes
pub struct Network {
    nodes: Vec<Node>,
}

impl Network {
    pub fn run(&mut self) {
        todo!()
    }

    pub fn get(&self, id: SystemIDType) -> Option<&Node> {
        self.nodes.iter().find(|node| node.system_id == id)
    }
}

/// A node during LIE Exchange
pub struct Node {
    /// The list of available physical neighbors.
    links: Vec<Link>,
    /// If not None, then the Node will end up with a discovered_level equal to this value at the end
    /// of LIE exchange (or else the LIE exchange will fail). Otherwise, the Node will discover it's
    /// own level itself.
    configured_level: Option<LevelType>,
    /// The actual level of this node. At the start of LIE exchange, this is None, as the node does
    /// not yet know it's level. By the end of LIE exchange, this value is Some.
    /// This should match configured_level if configured_level is not None.
    discovered_level: Option<LevelType>,
    system_id: SystemIDType,
}

impl Node {
    pub fn new(configured_level: Option<LevelType>, system_id: SystemIDType) -> Node {
        Node {
            links: vec![],
            configured_level,
            discovered_level: None,
            system_id,
        }
    }

    pub fn add_link(&mut self, other: &Node) {
        self.links.push(Link {
            lie_state: LIEState::OneWay,
            other: other.system_id,
            external_event_queue: VecDeque::new(),
            chained_event_queue: VecDeque::new(),
        })
    }

    pub fn on_timer(&mut self) {
        todo!()
    }

    pub fn on_packet_recv(&mut self) {
        todo!()
    }
}

/// A Link representing a connection from one Node to another Node. Note that these are physical Links
/// (that is to say, they are links which are physical present in the topology, but not nessecarily
/// links which that will be considered to be logically present in the topology later on.)
/// Note that this struct represents only one direction in a link--the other linked Node also has it's
/// own Link pointing back to the first Node.
struct Link {
    /// Determines if a link is logically present in the topology. If the LIEState is ThreeWay, then
    /// the link is logically present. Otherwise, it is not.
    lie_state: LIEState,
    external_event_queue: VecDeque<LIEEvent>,
    chained_event_queue: VecDeque<LIEEvent>,
    /// The system id of the other node in this link.
    other: SystemIDType,
}

impl Link {
    pub fn process_next_lie_event(&mut self) {
        // fetch an event out of (one of?) the queues and process it.
        todo!()
    }

    fn process_lie_event(
        &mut self,
        event: LIEEvent,
    ) -> (LIEState, &'static [LIEEvent], &'static [fn(&mut Link)]) {
        match (self.lie_state, event) {
            (LIEState::OneWay, LIEEvent::TimerTick) => todo!(),
            (LIEState::OneWay, LIEEvent::LevelChanged) => todo!(),
            (LIEState::OneWay, LIEEvent::HALChanged) => todo!(),
            (LIEState::OneWay, LIEEvent::HATChanged) => todo!(),
            (LIEState::OneWay, LIEEvent::HALSChanged) => todo!(),
            (LIEState::OneWay, LIEEvent::LieRcvd) => todo!(),
            (LIEState::OneWay, LIEEvent::NewNeighbor) => todo!(),
            (LIEState::OneWay, LIEEvent::ValidReflection) => todo!(),
            (LIEState::OneWay, LIEEvent::NeighborDroppedReflection) => todo!(),
            (LIEState::OneWay, LIEEvent::NeighborChangedLevel) => todo!(),
            (LIEState::OneWay, LIEEvent::NeighborChangedAddress) => todo!(),
            (LIEState::OneWay, LIEEvent::UnacceptableHeader) => todo!(),
            (LIEState::OneWay, LIEEvent::MTUMismatch) => todo!(),
            (LIEState::OneWay, LIEEvent::NeighborChangedMinorFields) => todo!(),
            (LIEState::OneWay, LIEEvent::HoldtimeExpired) => todo!(),
            (LIEState::OneWay, LIEEvent::MultipleNeighbors) => todo!(),
            (LIEState::OneWay, LIEEvent::MultipleNeighborsDone) => todo!(),
            (LIEState::OneWay, LIEEvent::FloodLeadersChanged) => todo!(),
            (LIEState::OneWay, LIEEvent::SendLie) => todo!(),
            (LIEState::OneWay, LIEEvent::UpdateZTPOffer) => todo!(),
            (LIEState::TwoWay, LIEEvent::TimerTick) => todo!(),
            (LIEState::TwoWay, LIEEvent::LevelChanged) => todo!(),
            (LIEState::TwoWay, LIEEvent::HALChanged) => todo!(),
            (LIEState::TwoWay, LIEEvent::HATChanged) => todo!(),
            (LIEState::TwoWay, LIEEvent::HALSChanged) => todo!(),
            (LIEState::TwoWay, LIEEvent::LieRcvd) => todo!(),
            (LIEState::TwoWay, LIEEvent::NewNeighbor) => todo!(),
            (LIEState::TwoWay, LIEEvent::ValidReflection) => todo!(),
            (LIEState::TwoWay, LIEEvent::NeighborDroppedReflection) => todo!(),
            (LIEState::TwoWay, LIEEvent::NeighborChangedLevel) => todo!(),
            (LIEState::TwoWay, LIEEvent::NeighborChangedAddress) => todo!(),
            (LIEState::TwoWay, LIEEvent::UnacceptableHeader) => todo!(),
            (LIEState::TwoWay, LIEEvent::MTUMismatch) => todo!(),
            (LIEState::TwoWay, LIEEvent::NeighborChangedMinorFields) => todo!(),
            (LIEState::TwoWay, LIEEvent::HoldtimeExpired) => todo!(),
            (LIEState::TwoWay, LIEEvent::MultipleNeighbors) => todo!(),
            (LIEState::TwoWay, LIEEvent::MultipleNeighborsDone) => todo!(),
            (LIEState::TwoWay, LIEEvent::FloodLeadersChanged) => todo!(),
            (LIEState::TwoWay, LIEEvent::SendLie) => todo!(),
            (LIEState::TwoWay, LIEEvent::UpdateZTPOffer) => todo!(),
            (LIEState::ThreeWay, LIEEvent::TimerTick) => todo!(),
            (LIEState::ThreeWay, LIEEvent::LevelChanged) => todo!(),
            (LIEState::ThreeWay, LIEEvent::HALChanged) => todo!(),
            (LIEState::ThreeWay, LIEEvent::HATChanged) => todo!(),
            (LIEState::ThreeWay, LIEEvent::HALSChanged) => todo!(),
            (LIEState::ThreeWay, LIEEvent::LieRcvd) => todo!(),
            (LIEState::ThreeWay, LIEEvent::NewNeighbor) => todo!(),
            (LIEState::ThreeWay, LIEEvent::ValidReflection) => todo!(),
            (LIEState::ThreeWay, LIEEvent::NeighborDroppedReflection) => todo!(),
            (LIEState::ThreeWay, LIEEvent::NeighborChangedLevel) => todo!(),
            (LIEState::ThreeWay, LIEEvent::NeighborChangedAddress) => todo!(),
            (LIEState::ThreeWay, LIEEvent::UnacceptableHeader) => todo!(),
            (LIEState::ThreeWay, LIEEvent::MTUMismatch) => todo!(),
            (LIEState::ThreeWay, LIEEvent::NeighborChangedMinorFields) => todo!(),
            (LIEState::ThreeWay, LIEEvent::HoldtimeExpired) => todo!(),
            (LIEState::ThreeWay, LIEEvent::MultipleNeighbors) => todo!(),
            (LIEState::ThreeWay, LIEEvent::MultipleNeighborsDone) => todo!(),
            (LIEState::ThreeWay, LIEEvent::FloodLeadersChanged) => todo!(),
            (LIEState::ThreeWay, LIEEvent::SendLie) => todo!(),
            (LIEState::ThreeWay, LIEEvent::UpdateZTPOffer) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::TimerTick) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::LevelChanged) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::HALChanged) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::HATChanged) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::HALSChanged) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::LieRcvd) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::NewNeighbor) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::ValidReflection) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::NeighborDroppedReflection) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::NeighborChangedLevel) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::NeighborChangedAddress) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::UnacceptableHeader) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::MTUMismatch) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::NeighborChangedMinorFields) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::HoldtimeExpired) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::MultipleNeighbors) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::MultipleNeighborsDone) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::FloodLeadersChanged) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::SendLie) => todo!(),
            (LIEState::MultipleNeighborsWait, LIEEvent::UpdateZTPOffer) => todo!(),
        }
    }

    pub fn send_lie_event() {
        todo!()
    }
}

#[derive(Debug, Clone, Copy)]
enum LIEState {
    OneWay,
    TwoWay,
    ThreeWay,
    MultipleNeighborsWait,
}

#[derive(Debug, Clone, Copy)]
enum LIEEvent {
    /// One second timer tick, i.e. the event is generated for FSM by some external entity once a
    /// second. To be quietly ignored if transition does not exist.
    TimerTick,
    /// Node's level has been changed by ZTP or configuration. This is provided by the ZTP FSM.
    LevelChanged,
    /// Best HAL computed by ZTP has changed. This is provided by the ZTP FSM.
    HALChanged,
    /// HAT computed by ZTP has changed. This is provided by the ZTP FSM.
    HATChanged,
    /// Set of HAL offering systems computed by ZTP has changed. This is provided by the ZTP FSM.
    HALSChanged,
    /// Received LIE on the interface.
    LieRcvd,
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

mod test {
    use crate::models::common::{LevelType, LEAF_LEVEL, TOP_OF_FABRIC_LEVEL};

    use super::{Network, Node};

    #[test]
    #[ignore = "not yet implemented"]
    fn two_nodes() {
        let id_a = 0;
        let id_b = 1;
        let mut top_of_fabric = Node::new(Some(TOP_OF_FABRIC_LEVEL), id_a);
        let mut leaf_node = Node::new(None, id_b);
        top_of_fabric.add_link(&leaf_node);
        leaf_node.add_link(&top_of_fabric);

        let mut network = Network {
            nodes: vec![top_of_fabric, leaf_node],
        };
        network.run();

        let top_of_fabric = network.get(id_a).unwrap();
        let leaf_node = network.get(id_b).unwrap();
        assert_eq!(top_of_fabric.discovered_level, Some(TOP_OF_FABRIC_LEVEL));
        assert_eq!(leaf_node.discovered_level, Some(LEAF_LEVEL));
    }
}
