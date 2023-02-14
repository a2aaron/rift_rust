use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::Duration,
};

use rand::seq::index;
use serde::Serialize;

use crate::{
    lie_exchange::{self, LeafFlags, LieEvent, LieState, LieStateMachine, Timer, ZtpStateMachine},
    models::{
        common::{self, LinkIDType},
        encoding::{PacketContent, ProtocolPacket},
    },
    packet::{self, Nonce, OuterSecurityEnvelopeHeader, PacketNumber, SecretKeyStore},
    socket::{RecvPacketError, RecvPacketResult, RiftSocket},
    tie_exchange::{LinkInfo, TieStateMachine},
    topology::{NodeDescription, TopologyDescription},
    wrapper::SystemID,
};

/// Represents a network of nodes.
#[derive(Serialize)]
pub struct Network {
    nodes: Vec<Node>,
    #[serde(skip)]
    keys: SecretKeyStore,
}

impl Network {
    /// Create a network from a topology description file. The passivity determines which type of
    /// nodes are actually created. The passivity determines which types of nodes are made. Typically,
    /// passivity is used for debugging purposes.
    pub fn from_desc(desc: &TopologyDescription, passivity: Passivity) -> io::Result<Network> {
        let nodes = desc
            .get_nodes()
            .iter()
            .filter(|node| match passivity {
                Passivity::PassiveOnly => node.passive,
                Passivity::NonPassiveOnly => !node.passive,
                Passivity::Both => true,
            })
            .map(|node_desc| Node::from_desc(node_desc))
            .collect::<io::Result<_>>()?;

        Ok(Network {
            nodes,
            keys: desc.get_keys(),
        })
    }

    /// Run the network, sending and receving packets to and from the nodes.
    pub fn step(&mut self) -> Result<(), Box<dyn Error>> {
        for i in index::sample(&mut rand::thread_rng(), self.nodes.len(), self.nodes.len()) {
            let node = &mut self.nodes[i];
            node.step(&self.keys)?;
        }

        // self.nodes.shuffle(&mut rand::thread_rng());
        Ok(())
    }
}

/// A node. A node may contain one or more Links, which are the node's physical neighbors.
#[derive(Serialize)]
struct Node {
    links: Vec<Link>,
    ztp_fsm: ZtpStateMachine,
    #[serde(flatten)]
    node_info: NodeInfo,
}

impl Node {
    /// Create a node from a NodeDescription. This method will fail if the addresses specified in the
    /// NodeDescription cannot be bound to.
    fn from_desc(node_desc: &NodeDescription) -> io::Result<Node> {
        let configured_level = Option::from(node_desc.level);
        let node_info = NodeInfo {
            node_name: Some(node_desc.name.clone()),
            configured_level,
            system_id: node_desc.system_id,
        };
        let links = node_desc
            .interfaces
            .iter()
            .enumerate()
            .map(|(local_link_id, link_desc)| {
                Link::from_desc(
                    local_link_id as LinkIDType,
                    node_info.clone(),
                    link_desc.name.clone(),
                    link_desc.lie_rx_addr(),
                    link_desc.lie_tx_addr(),
                    link_desc.tie_rx_addr(),
                )
            })
            .collect::<io::Result<_>>()?;

        Ok(Node {
            links,
            ztp_fsm: ZtpStateMachine::new(configured_level, LeafFlags),
            node_info,
        })
    }

    /// Run the node for one step.
    fn step(&mut self, key: &SecretKeyStore) -> Result<(), Box<dyn Error>> {
        let _span =
            tracing::debug_span!("node_step", node_name = self.node_info.node_name,).entered();

        // Run the ZTP FSM
        let lie_events = self.ztp_fsm.process_external_events();

        // Add any LIE events returned by the ZTP to the LIE FSMs
        for link in &mut self.links {
            for lie_event in &lie_events {
                link.lie_fsm.push_external_event(lie_event.clone());
            }
        }

        // Run each LIE FSM
        for link in &mut self.links {
            link.step(key, &mut self.ztp_fsm)?;
        }
        Ok(())
    }
}

/// A Link represents a physical connection between two nodes. Note that, even if two nodes are
/// _physically_ connected, they might not be _logically_ connected (in fact, the entire point of
/// RIFT is to determine which physical connections are logical).
#[derive(Serialize)]
struct Link {
    /// The socket managing the connection to the adjacent node.
    #[serde(skip)]
    link_socket: LinkSocket,
    /// The state machine for LIE exchange.
    lie_fsm: LieStateMachine,
    /// The state machine for TIE exchange.
    #[serde(skip)]
    tie_fsm: TieStateMachine,
    /// Additional information about the link which doesn't really belong anywhere else.
    #[serde(flatten)]
    node_info: NodeInfo,
    #[serde(skip)]
    // The timer used for sending TimerTick events periodically.
    last_timer_tick: Timer,
    /// The timer used for doing TIDE generation and TIE sending periodically.
    #[serde(skip)]
    tie_timer: Timer,
}

impl Link {
    /// Create a node from a NodeDescription. This method will fail if `lie_rx_addr` or `lie_tx_addr`
    /// cannot be bound to.
    fn from_desc(
        local_link_id: LinkIDType,
        node_info: NodeInfo,
        link_name: String,
        lie_rx_addr: SocketAddr,
        lie_tx_addr: SocketAddr,
        tie_rx_addr: SocketAddr,
    ) -> io::Result<Link> {
        Ok(Link {
            link_socket: LinkSocket::new(
                link_name,
                local_link_id,
                lie_rx_addr,
                lie_tx_addr,
                tie_rx_addr,
                common::DEFAULT_MTU_SIZE as usize,
            )?,
            lie_fsm: LieStateMachine::new(node_info.configured_level),
            tie_fsm: TieStateMachine::new(),
            node_info,
            last_timer_tick: Timer::new(Duration::from_secs(1)),
            tie_timer: Timer::new(Duration::from_secs(1)),
        })
    }

    pub fn step(
        &mut self,
        keys: &SecretKeyStore,
        ztp_fsm: &mut ZtpStateMachine,
    ) -> Result<(), Box<dyn Error>> {
        // Returns Some if the Link is currently in ThreeWay along with some information about the Link.
        fn is_threeway(link: &Link) -> Option<LinkInfo> {
            if link.lie_fsm.lie_state == LieState::ThreeWay {
                Some(crate::tie_exchange::LinkInfo {
                    local_system_id: link.node_info.system_id,
                    local_level: link.lie_fsm.level().unwrap(),
                    neighbor: link.lie_fsm.neighbor.clone().unwrap(),
                })
            } else {
                None
            }
        }

        let _span = tracing::debug_span!(
            "link_step",
            node_name = self.node_info.node_name,
            link_name = self.link_socket.name,
        )
        .entered();

        let packets = self.link_socket.recv_packets(keys)?;
        for (packet, address) in packets {
            match packet.content {
                PacketContent::Lie(content) => self.lie_fsm.push_external_event(LieEvent::LieRcvd(
                    address.ip(),
                    packet.header,
                    content,
                )),
                PacketContent::Tide(tide) => {
                    let tide = &tide.into();
                    if let Some(link_info) = is_threeway(self) {
                        let from_northbound = match packet.header.level {
                            Some(level) => {
                                Some((level + 1) as lie_exchange::Level) == self.lie_fsm.level()
                            }
                            None => false,
                        };

                        if let Err(err) =
                            self.tie_fsm.process_tide(&link_info, from_northbound, tide)
                        {
                            tracing::error!(tide =? tide, err =? err, "Error while processing TIDE");
                        }
                    }
                }
                PacketContent::Tire(tire) => {
                    if let Some(link_info) = is_threeway(self) {
                        self.tie_fsm.process_tire(&link_info, &tire.into())
                    }
                }
                PacketContent::Tie(tie) => {
                    if let Some(link_info) = is_threeway(self) {
                        self.tie_fsm.process_tie(&link_info, &tie.into())
                    }
                }
            }
        }

        if self.last_timer_tick.is_expired() {
            self.lie_fsm.push_external_event(LieEvent::TimerTick);
            self.last_timer_tick.start()
        }

        self.lie_fsm
            .process_external_events(&mut self.link_socket, &self.node_info, ztp_fsm)?;

        if self.lie_fsm.lie_state == LieState::ThreeWay {
            if self.tie_timer.is_expired() {
                self.tie_timer.start();
                self.tie_fsm
                    .generate_tide(self.link_socket.tirdes_per_pkt());
                self.tie_fsm.send_ties();
            }

            self.tie_fsm.generate_tire();
        }

        Ok(())
    }
}

/// A wrapper struct for the LIE send and recv sockets. This struct also contains the state required
/// for maintaining a connection, but not any of the LIE exchange stat emachine information. This
/// seperation is done so that LieStateMachine doesn't have to contain self-referential structs.
pub struct LinkSocket {
    /// The socket that this link will receive LIE packets from.
    lie_rx_socket: Box<dyn RiftSocket>,
    /// The socket that this link will send LIE packets to.
    lie_tx_socket: Box<dyn RiftSocket>,
    /// The port that this link will receive TIE packets from.
    /// TODO: This should probably become a RiftSocket eventually.
    tie_rx_socket: Box<dyn RiftSocket>,
    /// The name of this link, typically specified by the topology description file
    pub name: String,
    /// The maximum transmissible unit size.
    pub mtu: usize,
    /// The local link ID. This value must be unique across all the links on a particular node, but
    /// does not need to be unique across nodes.
    pub local_link_id: LinkIDType,
    /// The packet number used when sending out a LIE. This is incremented each time a packet is sent.
    // TODO: the packet numbers are "per adjacency, per packet", so there should probably be 4 of these
    // however it also says the packet numbers are optional, so w/e
    packet_number: PacketNumber,
    /// The weak local nonce value used when sending out a LIE. This is used for comptuation of the
    /// security envelope. This value is local to this particular node, and is incremented according
    /// to the rules as defined in the spec:
    /// An implementation SHOULD increment a chosen nonce on every LIE FSM transition that ends up
    /// in a different state from the previous one and MUST increment its nonce at least every
    /// `nonce_regeneration_interval` (such considerations allow for efficient implementations
    /// without opening a significant security risk).
    /// TODO: Currently, the weak_nonce_local simply increments every packet. This is probably the
    /// wrong thing to do.
    weak_nonce_local: Nonce,
    /// The weak remote nonce value when sending out a LIE. This is used for computation of the
    /// security envelope. This value is set whenever a packet is received on this LinkSocket.
    weak_nonce_remote: Nonce,
}

impl LinkSocket {
    /// Create a new LinkSocket. This function will fail if `lie_rx_addr` cannot be bound to or if
    /// `lie_tx_addr` cannot be connected to. Additionally, this function fails if `lie_rx_addr` is
    /// a multicast address and cannot be joined.
    fn new(
        name: String,
        local_link_id: LinkIDType,
        lie_rx_addr: SocketAddr,
        lie_tx_addr: SocketAddr,
        tie_rx_addr: SocketAddr,
        mtu: usize,
    ) -> io::Result<LinkSocket> {
        let _span = tracing::info_span!("LinkSocket::new", interface = name).entered();
        // For the receive socket, we bind to the receive address since we are only listening on
        // this socket.
        let lie_rx_socket = UdpSocket::bind(lie_rx_addr)?;
        tracing::info!(recv_addr =% lie_rx_addr, send_addr =% lie_tx_addr, "recv socket bound");

        // If the receive address is multicast, then we need to join the mutlicast group. We leave
        // the interface unspecified here, since we don't care about which particular interface we
        // receive messages on (we want all of them).
        if lie_rx_addr.ip().is_multicast() {
            match &lie_rx_addr.ip() {
                IpAddr::V4(multiaddr) => {
                    lie_rx_socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)?
                }
                IpAddr::V6(multiaddr) => lie_rx_socket.join_multicast_v6(multiaddr, 0)?,
            }
            tracing::info!(
                address =% lie_rx_addr,
                "recv socket joined multicast group",
            );
        }

        // Set the receving socket to non-blocking.
        lie_rx_socket.set_nonblocking(true)?;

        // For the send socket, we bind to an unspecified address, since we don't care about the
        // particular address we send from (we will let the OS pick for us).
        let unspecified = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let lie_tx_socket = UdpSocket::bind(unspecified)?;
        // UDP is connectionless, however, Rust provides a connection abstraction,. This technically
        // doesn't do anything other than default where `lie_tx_socket.send()` sends to by default.
        lie_tx_socket.connect(lie_tx_addr)?;

        let tie_rx_socket = UdpSocket::bind(tie_rx_addr)?;
        tie_rx_socket.set_nonblocking(true)?;
        // TODO: does the TIE rx socket need to be on multicast?

        Ok(LinkSocket {
            name,
            local_link_id,
            lie_rx_socket: Box::new(lie_rx_socket),
            lie_tx_socket: Box::new(lie_tx_socket),
            tie_rx_socket: Box::new(tie_rx_socket),
            mtu,
            packet_number: PacketNumber::from(1),
            weak_nonce_local: Nonce::from(1),
            weak_nonce_remote: Nonce::Invalid,
        })
    }

    pub fn recv_packets(
        &mut self,
        keys: &SecretKeyStore,
    ) -> Result<Vec<(ProtocolPacket, SocketAddr)>, RecvPacketError> {
        let mut buf = vec![0; self.mtu];

        let mut packets = vec![];

        let lie_result = self.lie_rx_socket.recv_packet(&mut buf, keys);

        // We set our remote nonce to their local nonce we recieved.
        if let RecvPacketResult::Packet {
            outer_header,
            packet,
            address,
        } = lie_result
        {
            self.weak_nonce_remote = outer_header.weak_nonce_local;
            packets.push((packet, address));
        } else if let RecvPacketResult::Err(err) = lie_result {
            return Err(err);
        }

        let tie_result = self.tie_rx_socket.recv_packet(&mut buf, keys);
        if let RecvPacketResult::Packet {
            outer_header,
            packet,
            address,
        } = tie_result
        {
            self.weak_nonce_remote = outer_header.weak_nonce_local;
            packets.push((packet, address));
        } else if let RecvPacketResult::Err(err) = tie_result {
            return Err(err);
        }
        Ok(packets)
    }

    pub fn send_packet(&mut self, packet: &ProtocolPacket) -> io::Result<usize> {
        let outer_header = OuterSecurityEnvelopeHeader::new(
            self.weak_nonce_local,
            self.weak_nonce_remote,
            self.packet_number,
        );
        let buf = packet::serialize(outer_header, packet);
        let result = self.lie_tx_socket.send(&buf);

        // TODO: These probably need to be incremented in different locations.
        self.packet_number = self.packet_number + 1;
        self.weak_nonce_local = self.weak_nonce_local + 1;

        result
    }

    pub fn flood_port(&self) -> u16 {
        self.tie_rx_socket.get().local_addr().unwrap().port()
    }

    /// The constant `TIRDEs_PER_PKT` SHOULD be computed per interface and used by the
    /// implementation to limit the amount of TIE headers per TIDE so the sent TIDE PDU does not
    /// exceed interface MTU
    fn tirdes_per_pkt(&self) -> usize {
        5 // TODO: i made up this number
    }
}

/// A convience struct for keep track of node specific information.
#[derive(Serialize, Clone)]
pub struct NodeInfo {
    /// The name of this node.
    pub node_name: Option<String>,
    /// The configured level. See [topology::Level] for the specific configuration options.
    pub configured_level: Option<lie_exchange::Level>,
    /// The system ID of this node. Note that this is unique across all of the nodes.
    pub system_id: SystemID,
}

/// Which nodes to create from topology description files.
pub enum Passivity {
    /// Create only nodes marked passive.
    PassiveOnly,
    /// Create only nodes marked non-passive.
    NonPassiveOnly,
    /// Create both passive and non-passive nodes.
    Both,
}
