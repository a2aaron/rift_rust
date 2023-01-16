use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket},
};

use crate::{
    lie_exchange::{Level, LieEvent, LieStateMachine},
    models::{
        common,
        encoding::{PacketContent, ProtocolPacket},
    },
    packet::{self, Nonce, OuterSecurityEnvelopeHeader, PacketNumber, SecretKeyStore},
    topology::{GlobalConstants, Interface, NodeDescription, TopologyDescription},
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
            .map(|link_desc| {
                let configured_level = node_desc.level.into();
                Link::from_desc(rx_lie_v4, configured_level, link_desc)
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
    lie_socket: UdpSocket,
    // TODO: the packet numbers are "per adjacency, per packet", so there should probably be 4 of these
    // however it also says the packet numbers are optional, so w/e
    packet_number: PacketNumber,
    weak_nonce_local: Nonce,
    weak_nonce_remote: Nonce,
    lie_fsm: LieStateMachine,
}

impl Link {
    pub fn from_desc(
        lie_rx_mcast_address: Ipv4Addr,
        configured_level: Level,
        link_desc: &Interface,
    ) -> io::Result<Link> {
        let rx_lie_port = link_desc
            .rx_lie_port
            .unwrap_or(common::DEFAULT_LIE_UDP_PORT as u16);

        // todo: ipv6
        let addr = SocketAddrV4::new(lie_rx_mcast_address, rx_lie_port);
        let lie_socket = UdpSocket::bind(addr)?;

        if lie_rx_mcast_address.is_multicast() {
            lie_socket.join_multicast_v4(&lie_rx_mcast_address, &Ipv4Addr::UNSPECIFIED)?;
        }
        println!("Interface {}: recving on {}", link_desc.name, addr);
        Ok(Link {
            lie_socket,
            packet_number: PacketNumber::from(1),
            weak_nonce_local: Nonce::from(1),
            weak_nonce_remote: Nonce::Invalid,
            lie_fsm: LieStateMachine::new(configured_level),
        })
    }

    pub fn step(&mut self, keys: &SecretKeyStore) {
        self.lie_fsm.process_external_event();
        match self.recv_packet(keys) {
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

    pub fn recv_packet(
        &self,
        keys: &SecretKeyStore,
    ) -> Result<(ProtocolPacket, SocketAddr), Box<dyn Error>> {
        let mut bytes: Vec<u8> = vec![0; common::DEFAULT_MTU_SIZE as usize];
        let (length, address) = self.lie_socket.recv_from(&mut bytes)?;
        bytes.resize(length, 0u8);
        let packet = packet::parse_and_validate(&bytes, keys)?;

        // TODO: set weak_nonce_remote based on packet data?
        Ok((packet, address))
    }

    pub fn send_packet(&mut self, packet: &ProtocolPacket) -> io::Result<usize> {
        let outer_header = OuterSecurityEnvelopeHeader::new(
            self.weak_nonce_local,
            self.weak_nonce_remote,
            self.packet_number,
        );
        let buf = packet::serialize(outer_header, packet);

        let result = self.lie_socket.send(&buf);

        // TODO: These probably need to be incremented in different locations.
        self.packet_number = self.packet_number + 1;
        self.weak_nonce_local = self.weak_nonce_local + 1;

        result
    }
}

pub enum Passivity {
    PassiveOnly,
    NonPassiveOnly,
    Both,
}
