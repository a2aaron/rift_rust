use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket},
};

use crate::{
    lie_exchange::{self, LieEvent, LieStateMachine},
    models::{
        common,
        encoding::{PacketContent, ProtocolPacket},
    },
    packet::{self, Nonce, OuterSecurityEnvelopeHeader, PacketNumber, SecretKeyStore},
    topology::{GlobalConstants, Interface, NodeDescription, SystemID, TopologyDescription},
};

// 224.0.0.120
const DEFAULT_LIE_IPV4_MCAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 120);
// FF02::A1F7
const DEFAULT_LIE_IPV6_MCAST_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xA1F7);

/// Represents a network of nodes
pub struct Network {
    nodes: Vec<Node>,
    keys: SecretKeyStore,
}

impl Network {
    pub fn from_desc(desc: &TopologyDescription, passivity: Passivity) -> io::Result<Network> {
        let nodes = desc
            .get_nodes()
            .iter()
            .filter(|node| match passivity {
                Passivity::PassiveOnly => node.passive,
                Passivity::NonPassiveOnly => !node.passive,
                Passivity::Both => true,
            })
            .map(|node| Node::from_desc(node, &desc.constant))
            .collect::<io::Result<_>>()?;

        Ok(Network {
            nodes,
            keys: desc.get_keys(),
        })
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            for node in &mut self.nodes {
                node.step(&self.keys);
            }
        }
    }
}

/// A node
pub struct Node {
    links: Vec<Link>,
}

impl Node {
    pub fn from_desc(node_desc: &NodeDescription, constants: &GlobalConstants) -> io::Result<Node> {
        let rx_lie_v4 = node_desc.rx_lie_mcast_address.unwrap_or(
            constants
                .rx_mcast_address
                .unwrap_or(DEFAULT_LIE_IPV4_MCAST_ADDRESS),
        );
        let links = node_desc
            .interfaces
            .iter()
            .enumerate()
            .map(|(local_link_id, link_desc)| {
                let node_info = NodeInfo {
                    name: Some(node_desc.name.clone()),
                    configured_level: node_desc.level.into(),
                    lie_addr: rx_lie_v4.into(),
                    system_id: node_desc.system_id,
                };
                Link::from_desc(local_link_id as u32, node_info, link_desc)
            })
            .collect::<io::Result<_>>()?;

        Ok(Node { links })
    }

    pub fn step(&mut self, key: &SecretKeyStore) {
        for link in &mut self.links {
            link.step(key);
        }
    }
}

pub struct Link {
    link_socket: LinkSocket,
    lie_fsm: LieStateMachine,
    node_info: NodeInfo,
}

impl Link {
    pub fn from_desc(
        local_link_id: u32,
        node_info: NodeInfo,
        link_desc: &Interface,
    ) -> io::Result<Link> {
        let rx_lie_port = link_desc
            .rx_lie_port
            .unwrap_or(common::DEFAULT_LIE_UDP_PORT as u16);
        let tx_lie_port = link_desc
            .tx_lie_port
            .unwrap_or(common::DEFAULT_LIE_UDP_PORT as u16);

        // todo: ipv6
        let rx_addr = SocketAddrV4::new(node_info.lie_addr, rx_lie_port).into();
        let tx_addr = SocketAddrV4::new(node_info.lie_addr, tx_lie_port).into();

        Ok(Link {
            link_socket: LinkSocket::new(link_desc.name.clone(), local_link_id, rx_addr, tx_addr)?,
            lie_fsm: LieStateMachine::new(node_info.configured_level),
            node_info,
        })
    }

    pub fn step(&mut self, keys: &SecretKeyStore) {
        self.lie_fsm
            .process_external_event(&mut self.link_socket, &self.node_info);
        match self.link_socket.recv_packet(keys) {
            Ok((packet, address)) => {
                match packet.content {
                    PacketContent::Lie(content) => self.lie_fsm.push_external_event(
                        LieEvent::LieRcvd(address.ip(), packet.header, content),
                    ),
                    _ => (),
                }
            }
            Err(err) => println!("Did not recv packet: {}", err),
        }
    }
}

// Wrapper struct for a UdpSocket
pub struct LinkSocket {
    lie_rx_socket: UdpSocket,
    lie_tx_socket: UdpSocket,
    pub name: String,
    pub local_link_id: u32,
    pub lie_rx_addr: SocketAddr,
    pub lie_tx_addr: SocketAddr,
    // TODO: the packet numbers are "per adjacency, per packet", so there should probably be 4 of these
    // however it also says the packet numbers are optional, so w/e
    packet_number: PacketNumber,
    weak_nonce_local: Nonce,
    weak_nonce_remote: Nonce,
}

impl LinkSocket {
    pub fn new(
        name: String,
        local_link_id: u32,
        lie_rx_addr: SocketAddr,
        lie_tx_addr: SocketAddr,
    ) -> io::Result<LinkSocket> {
        let lie_rx_socket = UdpSocket::bind(lie_rx_addr)?;
        println!(
            "Interface {}: recving on {}, sending on {}",
            name, lie_rx_addr, lie_tx_addr
        );

        if lie_rx_addr.ip().is_multicast() {
            match &lie_rx_addr.ip() {
                IpAddr::V4(multiaddr) => {
                    lie_rx_socket.join_multicast_v4(multiaddr, &Ipv4Addr::UNSPECIFIED)?
                }
                IpAddr::V6(multiaddr) => lie_rx_socket.join_multicast_v6(multiaddr, 0)?,
            }
            println!(
                "Interface {}: joining multicast address for recv: {}",
                name, lie_rx_addr
            );
        }

        let unspecified = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let lie_tx_socket = UdpSocket::bind(unspecified)?;
        lie_tx_socket.connect(lie_tx_addr)?;

        Ok(LinkSocket {
            name,
            local_link_id,
            lie_rx_socket,
            lie_tx_socket,
            lie_rx_addr,
            lie_tx_addr,
            packet_number: PacketNumber::from(1),
            weak_nonce_local: Nonce::from(1),
            weak_nonce_remote: Nonce::Invalid,
        })
    }

    pub fn recv_packet(
        &self,
        keys: &SecretKeyStore,
    ) -> Result<(ProtocolPacket, SocketAddr), Box<dyn Error>> {
        let mut bytes: Vec<u8> = vec![0; common::DEFAULT_MTU_SIZE as usize];
        let (length, address) = self.lie_rx_socket.recv_from(&mut bytes)?;
        bytes.resize(length, 0u8);
        let packet = packet::parse_and_validate(&bytes, keys)?;

        // TODO: set weak_nonce_remote based on packet data?
        Ok((packet, address))
    }

    // TODO: THIS SUCKS (move tx_lie_port into this struct instead of passing it in. maybe also put LinkInfo into this struct)
    // TODO: maybe definitely add the address here?
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
}

pub struct NodeInfo {
    /// Node or adjacency name.
    pub name: Option<String>,
    pub configured_level: lie_exchange::Level,
    pub lie_addr: Ipv4Addr,
    pub system_id: SystemID,
}

pub enum Passivity {
    PassiveOnly,
    NonPassiveOnly,
    Both,
}
