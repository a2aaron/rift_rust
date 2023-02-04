use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

pub trait RiftSocket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
    fn get(&self) -> &UdpSocket;
}

impl RiftSocket for UdpSocket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn get(&self) -> &UdpSocket {
        self
    }
}

pub struct ChaosSocket {
    socket: UdpSocket,
    recv_fail_chance: f32,
    send_fail_chance: f32,
}

impl ChaosSocket {
    pub fn new(socket: UdpSocket) -> ChaosSocket {
        ChaosSocket {
            socket,
            recv_fail_chance: 0.2,
            send_fail_chance: 0.2,
        }
    }
}

impl RiftSocket for ChaosSocket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if rand::random::<f32>() < self.recv_fail_chance {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            self.socket.recv_from(buf)
        }
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if rand::random::<f32>() < self.send_fail_chance {
            tracing::debug!("send fail!");
            Ok(buf.len())
        } else {
            self.socket.send(buf)
        }
    }

    fn get(&self) -> &UdpSocket {
        &self.socket
    }
}
