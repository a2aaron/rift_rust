use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    str::FromStr,
};

fn main() {
    let send_multicast_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 19980);

    // We bind to Unspecified here because "bind" is what address you are listening to, but since
    // the socket is sending, we do not care about receiving data.
    let send_socket = UdpSocket::bind(send_multicast_addr).unwrap();

    // We bind to the multicast address to receive data.
    let recv_multicast_addr = SocketAddrV4::new(Ipv4Addr::from_str("224.0.100.2").unwrap(), 20022);
    let recv_socket = UdpSocket::bind(recv_multicast_addr).unwrap();
    // This joins the multicast group. If we don't do this, then our recv_socket will never recv the
    // data, because it won't know it's in the multicast group.
    recv_socket
        .join_multicast_v4(recv_multicast_addr.ip(), &Ipv4Addr::UNSPECIFIED)
        .unwrap();

    // Connect the send socket to the address that the recv is listening on.
    send_socket.connect(recv_multicast_addr).unwrap();

    // Send some data!
    send_socket.send("Hello World!".as_bytes()).unwrap();

    // Receive some data!
    let mut buf = vec![0u8; 64];
    let length = recv_socket.recv(&mut buf).unwrap();

    println!("{:?}", std::str::from_utf8(&buf[..length]).unwrap());

    println!("send socket: {:?}", send_socket);
    println!("send loopback: {:?}", send_socket.multicast_loop_v4());
    println!("recv socket: {:?}", recv_socket);
    println!("recv loopback: {:?}", recv_socket.multicast_loop_v4());
}
