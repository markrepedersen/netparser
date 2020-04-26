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
pub fn show_ipv4(
    writer: &mut BufWriter<File>,
    frame: &frame::Frame,
    opts: &PacketOptions,
) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        writeln!(writer, "{:#?}", ip_packet)?;
    }
    Ok(())
}

/// Show IPv6 Packets as they come through the NIC.
pub fn show_ipv6(
    writer: &mut BufWriter<File>,
    frame: &frame::Frame,
    opts: &PacketOptions,
) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv6(ref ip_packet) = frame.payload {
        writeln!(writer, "{:#?}", ip_packet)?;
    }
    Ok(())
}

/// Show ARP Packets as they come through the NIC.
pub fn show_arp(writer: &mut BufWriter<File>, frame: &frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::ARP(ref ip_packet) = frame.payload {
        writeln!(writer, "{:#?}", ip_packet)?;
    }
    Ok(())
}

/// Show TCP Packets as they come through the NIC.
pub fn show_tcp(
    writer: &mut BufWriter<File>,
    frame: &frame::Frame,
    opts: &PacketOptions,
) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::TCP(ref tcp_packet) = ip_packet.payload {
            match tcp_packet {
                tcp::Packet {
                    src_port, dst_port, ..
                } if opts.port.is_some() => {
                    if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                        writeln!(writer, "{:#?}", tcp_packet)?;
                    }
                }
                _ => writeln!(writer, "{:#?}", tcp_packet)?,
            }
        }
    }
    Ok(())
}

/// Show UDP Packets as they come through the NIC.
pub fn show_udp(
    writer: &mut BufWriter<File>,
    frame: &frame::Frame,
    opts: &PacketOptions,
) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
            match udp_packet {
                udp::Datagram {
                    src_port, dst_port, ..
                } if opts.port.is_some() => {
                    if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                        writeln!(writer, "{:#?}", udp_packet)?;
                    }
                }
                _ => writeln!(writer, "{:#?}", udp_packet)?,
            }
        }
    }
    Ok(())
}

/// Show ICMP Packets as they come through the NIC.
pub fn show_icmp(writer: &mut BufWriter<File>, frame: &frame::Frame) -> Result<(), std::io::Error> {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ip::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
            writeln!(writer, "{:#?}", icmp_packet)?;
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
    pub port: Option<u16>,
    pub all: bool,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Write packets to desired output.
fn write_packet(
    mut writer: &mut BufWriter<File>,
    packet: &[u8],
    opts: &PacketOptions,
) -> Result<(), Box<dyn Error>> {
    match frame::Frame::parse(packet) {
        Ok((_remaining, frame)) => {
            if let PacketOptions { hex_dump: true, .. } = opts {
                writeln!(&mut writer, "{:X}", HexSlice::new(packet))?;
            }

            if let PacketOptions { json: true, .. } = opts {
                to_writer(&mut writer, &frame)?;
            }

            if let PacketOptions { all: true, .. } = opts {
                writeln!(&mut writer, "{:#?}", &frame)?;
            } else {
                if let PacketOptions { ipv4: true, .. } = opts {
                    show_ipv4(&mut writer, &frame, &opts)?;
                }

                if let PacketOptions { ipv6: true, .. } = opts {
                    show_ipv6(&mut writer, &frame, &opts)?;
                }

                if let PacketOptions { arp: true, .. } = opts {
                    show_arp(&mut writer, &frame)?;
                }

                if let PacketOptions { tcp: true, .. } = opts {
                    show_tcp(&mut writer, &frame, &opts)?;
                }

                if let PacketOptions { udp: true, .. } = opts {
                    show_udp(&mut writer, &frame, &opts)?;
                }

                if let PacketOptions { icmp: true, .. } = opts {
                    show_icmp(&mut writer, &frame)?;
                }
            }
        }
        Err(nom::Err::Error(e)) => println!("{:#?}", e),
        _ => unreachable!(),
    };
    Ok(())
}

/// Create the writer.
/// Stdout and file outputs are currently accepted only.
fn create_writer(opts: &PacketOptions) -> BufWriter<File> {
    if opts.json {
        let file_name = opts
            .file_name
            .clone()
            .expect("File name must also be given.");
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Unable to create file.");
        return BufWriter::new(file);
    } else {
        return BufWriter::new(unsafe { File::from_raw_fd(1) });
    };
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
    let mut writer = create_writer(&opts);

    loop {
        match rx.next() {
            Ok(packet) => write_packet(&mut writer, packet, opts)?,
            Err(e) => {
                panic!("An error occurred while reading packet: {}", e);
            }
        }
        writer.flush()?;
    }
}
