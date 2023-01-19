use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket},
};

use crate::{
    lie_exchange::{self, LieEvent, LieStateMachine},
    models::{
        common::{self, LinkIDType},
        encoding::{PacketContent, ProtocolPacket},
    },
    packet::{self, Nonce, OuterSecurityEnvelopeHeader, PacketNumber, SecretKeyStore},
    topology::{NodeDescription, SystemID, TopologyDescription},
};

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
            .map(|node_desc| Node::from_desc(node_desc))
            .collect::<io::Result<_>>()?;

        Ok(Network {
            nodes,
            keys: desc.get_keys(),
        })
    }

    pub fn run(&mut self) -> io::Result<()> {
        loop {
            for node in &mut self.nodes {
                node.step(&self.keys)?;
            }
        }
    }
}

/// A node
pub struct Node {
    links: Vec<Link>,
}

impl Node {
    pub fn from_desc(node_desc: &NodeDescription) -> io::Result<Node> {
        let links = node_desc
            .interfaces
            .iter()
            .enumerate()
            .map(|(local_link_id, link_desc)| {
                let node_info = NodeInfo {
                    name: Some(node_desc.name.clone()),
                    configured_level: node_desc.level.into(),
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

        Ok(Node { links })
    }

    pub fn step(&mut self, key: &SecretKeyStore) -> io::Result<()> {
        for link in &mut self.links {
            link.step(key)?;
        }
        Ok(())
    }
}

pub struct Link {
    link_socket: LinkSocket,
    lie_fsm: LieStateMachine,
    node_info: NodeInfo,
}

impl Link {
    pub fn from_desc(
        local_link_id: LinkIDType,
        node_info: NodeInfo,
        link_name: String,
        lie_rx_addr: SocketAddr,
        lie_tx_addr: SocketAddr,
    ) -> io::Result<Link> {
        Ok(Link {
            link_socket: LinkSocket::new(link_name, local_link_id, lie_rx_addr, lie_tx_addr)?,
            lie_fsm: LieStateMachine::new(
                node_info.configured_level,
                node_info.system_id,
                local_link_id,
            ),
            node_info,
        })
    }

    pub fn step(&mut self, keys: &SecretKeyStore) -> io::Result<()> {
        self.lie_fsm
            .process_external_event(&mut self.link_socket, &self.node_info)?;
        match self.link_socket.recv_packet(keys) {
            Ok((packet, address)) => {
                match packet.content {
                    PacketContent::Lie(content) => self.lie_fsm.push_external_event(
                        LieEvent::LieRcvd(address.ip(), packet.header, content),
                    ),
                    _ => (),
                }
            }
            Err(err) => println!("Could not recv packet: {}", err),
        }
        Ok(())
    }
}

// Wrapper struct for a UdpSocket
pub struct LinkSocket {
    lie_rx_socket: UdpSocket,
    lie_tx_socket: UdpSocket,
    pub name: String,
    pub local_link_id: LinkIDType,
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
        local_link_id: LinkIDType,
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
    pub system_id: SystemID,
}

pub enum Passivity {
    PassiveOnly,
    NonPassiveOnly,
    Both,
}
