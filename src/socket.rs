use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

use crate::{
    models::encoding::ProtocolPacket,
    packet::{self, OuterSecurityEnvelopeHeader, ParsingError, SecretKeyStore},
};

pub trait RiftSocket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
    fn get(&self) -> &UdpSocket;

    /// Receive one packet from the given socket.
    fn recv_packet<'a>(&self, buf: &'a mut [u8], keys: &SecretKeyStore) -> RecvPacketResult<'a> {
        match self.recv_from(buf) {
            Ok((length, address)) => {
                // Remove excess zeros from bytes vector.
                let buf = &buf[..length];
                match packet::parse_and_validate(&buf, keys) {
                    Ok((outer_header, _tie_header, packet)) => RecvPacketResult::Packet {
                        outer_header,
                        packet,
                        address,
                    },
                    Err(err) => RecvPacketResult::Err(err.into()),
                }
            }
            Err(err) => {
                // On WouldBlock, simply say there was no packet instead of erroring.
                if err.kind() == io::ErrorKind::WouldBlock {
                    RecvPacketResult::NoPacket
                } else {
                    RecvPacketResult::Err(err.into())
                }
            }
        }
    }
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

pub enum RecvPacketResult<'a> {
    NoPacket,
    Packet {
        outer_header: OuterSecurityEnvelopeHeader<'a>,
        packet: ProtocolPacket,
        address: SocketAddr,
    },
    Err(RecvPacketError),
}

#[derive(thiserror::Error, Debug)]
pub enum RecvPacketError {
    #[error("an io error occurred")]
    IOError(io::Error),
    #[error("a parsing error occurred")]
    ParsingError(ParsingError),
}

impl From<io::Error> for RecvPacketError {
    fn from(err: io::Error) -> Self {
        RecvPacketError::IOError(err)
    }
}

impl From<ParsingError> for RecvPacketError {
    fn from(err: ParsingError) -> Self {
        RecvPacketError::ParsingError(err)
    }
}
