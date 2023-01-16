use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket},
};

use crate::{
    models::{common, encoding::ProtocolPacket},
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
            for node in &self.nodes {
                for link in &node.links {
                    let packet = link.recv_packet(&self.keys)?;
                    println!("{:#?}", packet);
                }
            }
        }
    }
}

/// A node
pub struct Node {
    links: Vec<Link>,
}

impl Node {
    pub fn from_desc(desc: &NodeDescription, constants: &GlobalConstants) -> io::Result<Node> {
        let rx_lie_v4 = desc.rx_lie_mcast_address.unwrap_or(
            constants
                .rx_mcast_address
                .unwrap_or(DEFAULT_LIE_IPV4_MCAST_ADDRESS),
        );
        let links = desc
            .interfaces
            .iter()
            .map(|desc| Link::from_desc(rx_lie_v4, desc))
            .collect::<io::Result<_>>()?;

        Ok(Node { links })
    }
}

pub struct Link {
    lie_socket: UdpSocket,
    // TODO: the packet numbers are "per adjacency, per packet", so there should probably be 4 of these
    // however it also says the packet numbers are optional, so w/e
    packet_number: PacketNumber,
    weak_nonce_local: Nonce,
    weak_nonce_remote: Nonce,
}

impl Link {
    pub fn from_desc(lie_rx_mcast_address: Ipv4Addr, desc: &Interface) -> io::Result<Link> {
        let rx_lie_port = desc
            .rx_lie_port
            .unwrap_or(common::DEFAULT_LIE_UDP_PORT as u16);

        // todo: ipv6
        let addr = SocketAddrV4::new(lie_rx_mcast_address, rx_lie_port);
        let lie_socket = UdpSocket::bind(addr)?;

        if lie_rx_mcast_address.is_multicast() {
            lie_socket.join_multicast_v4(&lie_rx_mcast_address, &Ipv4Addr::UNSPECIFIED)?;
        }
        println!("Interface {}: recving on {}", desc.name, addr);
        Ok(Link {
            lie_socket,
            packet_number: PacketNumber::from(1),
            weak_nonce_local: Nonce::from(1),
            weak_nonce_remote: Nonce::Invalid,
        })
    }

    pub fn recv_packet(&self, keys: &SecretKeyStore) -> Result<ProtocolPacket, Box<dyn Error>> {
        let mut bytes: Vec<u8> = vec![0; common::DEFAULT_MTU_SIZE as usize];
        let length = self.lie_socket.recv(&mut bytes)?;
        bytes.resize(length, 0u8);
        let packet = packet::parse_and_validate(&bytes, keys)?;
        Ok(packet)
    }

    pub fn send_packet(&mut self, packet: &ProtocolPacket) -> io::Result<usize> {
        let outer_header = OuterSecurityEnvelopeHeader::new(
            self.weak_nonce_local,
            self.weak_nonce_remote,
            self.packet_number,
        );
        let buf = packet::serialize(outer_header, packet);

        self.lie_socket.send(&buf)
    }
}

pub enum Passivity {
    PassiveOnly,
    NonPassiveOnly,
    Both,
}
