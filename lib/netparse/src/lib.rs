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
pub mod tcp;
pub mod udp;
pub mod ux;

use hex_slice::HexSlice;
use pnet::datalink::{channel, interfaces, Channel};
use serde_json::to_writer;
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::io::FromRawFd,
};

/// Show IPv4 Packets as they come through the NIC.
pub fn show_ipv4(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        write!(writer, "{:#?}", ip_packet)?
    }
    Ok(())
}

/// Show IPv6 Packets as they come through the NIC.
pub fn show_ipv6(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv6(ref ip_packet) = frame.payload {
        write!(writer, "{:#?}", ip_packet)?
    }
    Ok(())
}

/// Show ARP Packets as they come through the NIC.
pub fn show_arp(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::ARP(ref ip_packet) = frame.payload {
        write!(writer, "{:#?}", ip_packet)?
    }
    Ok(())
}

/// Show TCP Packets as they come through the NIC.
pub fn show_tcp(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::TCP(ref tcp_packet) = ip_packet.payload {
            write!(writer, "{:#?}", tcp_packet)?
        }
    }
    Ok(())
}

/// Show UDP Packets as they come through the NIC.
pub fn show_udp(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
            write!(writer, "{:#?}", udp_packet)?
        }
    }
    Ok(())
}

/// Show ICMP Packets as they come through the NIC.
pub fn show_icmp(writer: &mut BufWriter<File>, frame: frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
            write!(writer, "{:#?}", icmp_packet)?
        }
    }
    Ok(())
}

/// The options for the packets to display.
#[derive(Default)]
pub struct PacketOptions {
    pub interface: String,
    pub json: bool,
    pub file_name: Option<String>,
    pub hex_dump: bool,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Run a loop, capturing the packets as described in <PacketOptions>.
pub fn run(opts: &PacketOptions) -> Result<(), Box<dyn Error>> {
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
    let mut writer = if opts.json {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(
                opts.file_name
                    .clone()
                    .expect("File name must also be given."),
            )
            .expect("Unable to create file.");
        BufWriter::new(file)
    } else {
        BufWriter::new(unsafe { File::from_raw_fd(1) })
    };

    loop {
        match rx.next() {
            Ok(packet) => match frame::Frame::parse(packet) {
                Ok((_remaining, frame)) => match opts {
                    PacketOptions { hex_dump: true, .. } => {
                        write!(&mut writer, "{:X}", HexSlice::new(packet))?
                    }
                    PacketOptions { json: true, .. } => to_writer(&mut writer, &frame)?,
                    PacketOptions { ipv4: true, .. } => show_ipv4(&mut writer, frame)?,
                    PacketOptions { ipv6: true, .. } => show_ipv6(&mut writer, frame)?,
                    PacketOptions { arp: true, .. } => show_arp(&mut writer, frame)?,
                    PacketOptions { tcp: true, .. } => show_tcp(&mut writer, frame)?,
                    PacketOptions { udp: true, .. } => show_udp(&mut writer, frame)?,
                    PacketOptions { icmp: true, .. } => show_icmp(&mut writer, frame)?,
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
