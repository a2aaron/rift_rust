use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use crate::{
    lie_exchange::{self, LeafFlags, LieEvent, LieStateMachine, ZtpStateMachine},
    models::{
        common::{self, LinkIDType},
        encoding::{PacketContent, ProtocolPacket},
    },
    packet::{self, Nonce, OuterSecurityEnvelopeHeader, PacketNumber, SecretKeyStore},
    topology::{NodeDescription, SystemID, TopologyDescription},
};

/// Represents a network of nodes.
pub struct Network {
    nodes: Vec<Node>,
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

    /// Run the network, sending and receving packets to and from the nodes. Note that this function
    /// does not return unless an error occurs.
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            for node in &mut self.nodes {
                node.step(&self.keys)?;
            }
        }
    }
}

/// A node. A node may contain one or more Links, which are the node's physical neighbors.
struct Node {
    links: Vec<Link>,
    ztp_fsm: ZtpStateMachine,
}

impl Node {
    /// Create a node from a NodeDescription. This method will fail if the addresses specified in the
    /// NodeDescription cannot be bound to.
    fn from_desc(node_desc: &NodeDescription) -> io::Result<Node> {
        let configured_level = node_desc.level.into();
        let links = node_desc
            .interfaces
            .iter()
            .enumerate()
            .map(|(local_link_id, link_desc)| {
                let node_info = NodeInfo {
                    node_name: Some(node_desc.name.clone()),
                    configured_level,
                    system_id: node_desc.system_id,
                };
                Link::from_desc(
                    local_link_id as LinkIDType,
                    node_info,
                    link_desc.name.clone(),
                    link_desc.lie_rx_addr(),
                    link_desc.lie_tx_addr(),
                )
            })
            .collect::<io::Result<_>>()?;

        Ok(Node {
            links,
            ztp_fsm: ZtpStateMachine::new(configured_level, LeafFlags),
        })
    }

    /// Run the node for one step.
    fn step(&mut self, key: &SecretKeyStore) -> io::Result<()> {
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
struct Link {
    /// The socket managing the connection to the adjacent node.
    link_socket: LinkSocket,
    /// The state machine for LIE exchange.
    lie_fsm: LieStateMachine,
    /// Additional information about the link which doesn't really belong anywhere else.
    node_info: NodeInfo,
    last_timer_tick: Option<Instant>,
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
    ) -> io::Result<Link> {
        Ok(Link {
            link_socket: LinkSocket::new(link_name, local_link_id, lie_rx_addr, lie_tx_addr)?,
            lie_fsm: LieStateMachine::new(node_info.configured_level),
            node_info,
            last_timer_tick: None,
        })
    }

    pub fn step(&mut self, keys: &SecretKeyStore, ztp_fsm: &mut ZtpStateMachine) -> io::Result<()> {
        match self.link_socket.recv_packet(keys) {
            RecvPacketResult::NoPacket => (),
            RecvPacketResult::Packet { packet, address } => {
                match packet.content {
                    PacketContent::Lie(content) => self.lie_fsm.push_external_event(
                        LieEvent::LieRcvd(address.ip(), packet.header, content),
                    ),
                    _ => (),
                }
            }
            RecvPacketResult::Err(err) => println!("Could not recv packet: {}", err),
        }

        let do_timer_tick = if let Some(last_timer_tick) = self.last_timer_tick {
            let duration = Instant::now().duration_since(last_timer_tick);
            duration > Duration::from_secs(1)
        } else {
            true
        };

        if do_timer_tick {
            self.lie_fsm.push_external_event(LieEvent::TimerTick);
            self.last_timer_tick = Some(Instant::now());
        }

        self.lie_fsm
            .process_external_events(&mut self.link_socket, &self.node_info, ztp_fsm)?;
        Ok(())
    }
}

/// A wrapper struct for the LIE send and recv sockets. This struct also contains the state required
/// for maintaining a connection, but not any of the LIE exchange stat emachine information. This
/// seperation is done so that LieStateMachine doesn't have to contain self-referential structs.
pub struct LinkSocket {
    /// The socket that this link will receive LIE packets from.
    lie_rx_socket: UdpSocket,
    /// The socket that this link will send LIE packets to.
    lie_tx_socket: UdpSocket,
    /// The name of this link, typically specified by the topology description file
    pub name: String,
    /// The maximum transmissible unit size.
    pub mtu: common::MTUSizeType,
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

        Ok(LinkSocket {
            name,
            local_link_id,
            lie_rx_socket,
            lie_tx_socket,
            mtu: common::DEFAULT_MTU_SIZE,
            packet_number: PacketNumber::from(1),
            weak_nonce_local: Nonce::from(1),
            weak_nonce_remote: Nonce::Invalid,
        })
    }

    pub fn recv_packet(&mut self, keys: &SecretKeyStore) -> RecvPacketResult {
        let mut bytes: Vec<u8> = vec![0; common::DEFAULT_MTU_SIZE as usize];
        match self.lie_rx_socket.recv_from(&mut bytes) {
            Ok((length, address)) => {
                bytes.resize(length, 0u8);
                match packet::parse_and_validate(&bytes, keys) {
                    Ok((outer_header, _tie_header, packet)) => {
                        // We set our remote to their local.
                        self.weak_nonce_remote = outer_header.weak_nonce_local;
                        RecvPacketResult::Packet { packet, address }
                    }
                    Err(err) => RecvPacketResult::Err(err.into()),
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    RecvPacketResult::NoPacket
                } else {
                    RecvPacketResult::Err(err.into())
                }
            }
        }
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
        // TODO
        0
    }
}

pub enum RecvPacketResult {
    NoPacket,
    Packet {
        packet: ProtocolPacket,
        address: SocketAddr,
    },
    Err(Box<dyn Error>),
}

/// A convience struct for keep track of node specific information.
pub struct NodeInfo {
    /// The name of this node.
    pub node_name: Option<String>,
    /// The configured level. See [topology::Level] for the specific configuration options.
    pub configured_level: lie_exchange::Level,
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
