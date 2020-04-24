pub mod arp;
pub mod blob;
pub mod dot11;
pub mod frame;
pub mod hex_slice;
pub mod icmp;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod parse;
pub mod serialize;
pub mod tcp;
pub mod udp;

use hex_slice::HexSlice;
use pnet::datalink::{channel, interfaces, Channel};
use std::{error::Error, fmt};

type IResult<T> = std::result::Result<T, NetparseError>;

#[derive(Debug, Clone)]
struct NetparseError;

impl fmt::Display for NetparseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unable to parse given frame.")
    }
}

impl Error for NetparseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Show IPv4 Packets as they come through the NIC.
pub fn show_ipv4(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

/// Show IPv6 Packets as they come through the NIC.
pub fn show_ipv6(frame: frame::Frame) {
    if let frame::Payload::IPv6(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

/// Show ARP Packets as they come through the NIC.
pub fn show_arp(frame: frame::Frame) {
    if let frame::Payload::ARP(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

/// Show TCP Packets as they come through the NIC.
pub fn show_tcp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::TCP(ref tcp_packet) = ip_packet.payload {
            println!("{:#?}", tcp_packet);
        }
    }
}

/// Show UDP Packets as they come through the NIC.
pub fn show_udp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
            println!("{:#?}", udp_packet);
        }
    }
}

/// Show ICMP Packets as they come through the NIC.
pub fn show_icmp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
            println!("{:#?}", icmp_packet);
        }
    }
}

/// The options for the packets to display.
#[derive(Default)]
pub struct PacketOptions {
    pub interface: String,
    pub hex_dump: bool,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Run a loop, capturing the packets as described in <PacketOptions>.
pub fn run(opts: PacketOptions) {
    let interface = interfaces()
        .into_iter()
        .filter(|iface| iface.name == opts.interface)
        .next()
        .unwrap();
    let (_tx, mut rx) = match channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Datalink channel error: {}", e),
    };

    println!("Using the following options when scanning for packets:");
    println!("- Interface Name: {}", interface.name);
    println!("- IP Addresses: {:?}", interface.ips);
    println!("- MAC Address: {:?}", interface.mac_address());

    println!("Scanning for packets...");

    loop {
        match rx.next() {
            Ok(packet) => match frame::Frame::parse(packet) {
                Ok((_remaining, frame)) => match opts {
                    PacketOptions { hex_dump: true, .. } => println!("{:X}", HexSlice::new(packet)),
                    PacketOptions { ipv4: true, .. } => show_ipv4(frame),
                    PacketOptions { ipv6: true, .. } => show_ipv6(frame),
                    PacketOptions { arp: true, .. } => show_arp(frame),
                    PacketOptions { tcp: true, .. } => show_tcp(frame),
                    PacketOptions { udp: true, .. } => show_udp(frame),
                    PacketOptions { icmp: true, .. } => show_icmp(frame),
                    _ => println!("{:#?}", frame),
                },
                Err(nom::Err::Error(e)) => println!("{:#?}", e),
                _ => unreachable!(),
            },
            Err(e) => {
                panic!("An error occurred while reading packet: {}", e);
            }
        }
    }
}
