use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket},
    sync::atomic::AtomicI64,
};

use crate::{
    lie_exchange::LinkFSM,
    models::{common, encoding},
    topology::{GlobalConstants, Interface, NodeDescription, TopologyDescription},
};

static ID: AtomicI64 = AtomicI64::new(0);

// 224.0.0.120
const DEFAULT_LIE_IPV4_MCAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 120);
// FF02::A1F7
const DEFAULT_LIE_IPV6_MCAST_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xA1F7);

/// Represents a network of nodes
pub struct Network {
    nodes: Vec<Node>,
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
        Ok(Network { nodes })
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            for node in &self.nodes {
                let packet = node.check_recv()?;
                if !packet.is_empty() {
                    println!("{:?}", packet);
                }
            }
        }
    }
}

/// A node
pub struct Node {
    is_passive: bool,
    links: Vec<Link>,
}

impl Node {
    pub fn from_desc(desc: &NodeDescription, constants: &GlobalConstants) -> io::Result<Node> {
        let rx_lie_v4 = desc.rx_lie_mcast_address.unwrap_or(
            constants
                .rx_mcast_address
                .unwrap_or((DEFAULT_LIE_IPV4_MCAST_ADDRESS)),
        );
        let links = desc
            .interfaces
            .iter()
            .map(|desc| Link::from_desc(rx_lie_v4, desc))
            .collect::<io::Result<_>>()?;

        Ok(Node {
            links,
            is_passive: desc.passive,
        })
    }

    pub fn packet_send(&mut self, packet: &[u8]) -> io::Result<usize> {
        todo!()
    }

    pub fn check_recv(&self) -> io::Result<Vec<u8>> {
        let mut vec: Vec<u8> = vec![0; common::DEFAULT_MTU_SIZE as usize];
        let length = self.links[0].lie_socket.recv(&mut vec)?;
        vec.resize(length, 0u8);
        Ok(vec)
    }
}

pub struct Link {
    lie_socket: UdpSocket,
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
        Ok(Link { lie_socket })
    }
}

pub enum Passivity {
    PassiveOnly,
    NonPassiveOnly,
    Both,
}
