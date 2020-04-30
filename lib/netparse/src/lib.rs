pub mod arp;
pub mod blob;
pub mod datalink;
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

use datalink::DatalinkFrame;
use hex_slice::HexSlice;
use pcap::{Capture, Linktype};
use serde::Serialize;
use serde_json::to_writer;
use std::{
    error::Error,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::io::FromRawFd,
};

/// The options for the packets to display.
#[derive(Default)]
pub struct PacketOptions {
    pub interface: String,
    pub json: bool,
    pub file_name: Option<String>,
    pub hex_dump: bool,
    pub wireless: bool,
    pub port: Option<u16>,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

fn write<T: Debug + Serialize, W: Write>(
    mut writer: &mut W,
    frame: &T,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    if json {
        to_writer(&mut writer, &frame)?;
    } else {
        writeln!(writer, "{:#?}", &frame)?;
    }
    Ok(())
}

/// Write packets to desired output.
fn write_packet<T: Write, D: DatalinkFrame>(
    mut writer: &mut T,
    frame: &D,
    opts: &PacketOptions,
) -> Result<(), Box<dyn Error>> {
    let mut verbose = true;
    let payload = frame.get_payload();

    if opts.ipv4 {
        verbose = false;
        if let Some(datalink::Payload::IPv4(ref ip_packet)) = payload {
            write(&mut writer, &ip_packet, opts.json)?;
        }
    }

    if opts.ipv6 {
        verbose = false;
        if let Some(datalink::Payload::IPv6(ref ip_packet)) = payload {
            write(&mut writer, &ip_packet, opts.json)?;
        }
    }

    if opts.arp {
        verbose = false;
        if let Some(datalink::Payload::ARP(ref arp_packet)) = payload {
            write(&mut writer, &arp_packet, opts.json)?;
        }
    }

    if opts.tcp {
        verbose = false;
        match payload {
            Some(datalink::Payload::IPv4(ref ip_packet)) => {
                if let ip::Payload::TCP(ref udp_packet) = ip_packet.payload {
                    match udp_packet {
                        tcp::Packet {
                            src_port, dst_port, ..
                        } if opts.port.is_some() => {
                            if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                                write(&mut writer, &udp_packet, opts.json)?;
                            }
                        }
                        _ => write(&mut writer, &udp_packet, opts.json)?,
                    }
                }
            }

            Some(datalink::Payload::IPv6(ref ip_packet)) => {
                if let ip::Payload::TCP(ref udp_packet) = ip_packet.payload {
                    match udp_packet {
                        tcp::Packet {
                            src_port, dst_port, ..
                        } if opts.port.is_some() => {
                            if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                                write(&mut writer, &udp_packet, opts.json)?;
                            }
                        }
                        _ => write(&mut writer, &udp_packet, opts.json)?,
                    }
                }
            }
            _ => {}
        }
    }

    if opts.udp {
        verbose = false;
        match payload {
            Some(datalink::Payload::IPv4(ref ip_packet)) => {
                if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
                    match udp_packet {
                        udp::Datagram {
                            src_port, dst_port, ..
                        } if opts.port.is_some() => {
                            if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                                write(&mut writer, &udp_packet, opts.json)?;
                            }
                        }
                        _ => write(&mut writer, &udp_packet, opts.json)?,
                    }
                }
            }

            Some(datalink::Payload::IPv6(ref ip_packet)) => {
                if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
                    match udp_packet {
                        udp::Datagram {
                            src_port, dst_port, ..
                        } if opts.port.is_some() => {
                            if *dst_port == opts.port.unwrap() || *src_port == opts.port.unwrap() {
                                write(&mut writer, &udp_packet, opts.json)?;
                            }
                        }
                        _ => write(&mut writer, &udp_packet, opts.json)?,
                    }
                }
            }
            _ => {}
        }
    }

    if opts.icmp {
        verbose = false;
        match payload {
            Some(datalink::Payload::IPv4(ref ip_packet)) => {
                if let ip::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
                    write(&mut writer, &icmp_packet, opts.json)?;
                }
            }
            Some(datalink::Payload::IPv6(ref ip_packet)) => {
                if let ip::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
                    write(&mut writer, &icmp_packet, opts.json)?;
                }
            }
            _ => {}
        }
    }

    if verbose {
        write(&mut writer, frame, opts.json)?;
    }

    writeln!(&mut writer)?;

    Ok(())
}

/// Create the writer.
/// Stdout and file are the only accepted outputs.
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

/// Capture packets, blocking until any are found.
pub fn run(opts: &PacketOptions) -> Result<(), Box<dyn Error>> {
    let mut cap = Capture::from_device(opts.interface.as_str())
        .unwrap()
        .promisc(true)
        .rfmon(opts.wireless)
        .buffer_size(10000)
        .open()
        .unwrap();
    let link_type = cap.get_datalink();
    let mut writer = create_writer(&opts);

    loop {
        match cap.next() {
            Ok(packet) => {
                if opts.hex_dump {
                    writeln!(&mut writer, "{:X}", HexSlice::new(packet.data))?;
                }

                match link_type {
                    Linktype(1) => {
                        if let Ok((_remaining, frame)) = frame::Frame::parse(packet.data) {
                            write_packet(&mut writer, &frame, opts)?
                        };
                    }
                    Linktype(105) | Linktype(119) | Linktype(127) | Linktype(163) => {
                        if let Ok((remaining, _)) = dot11::RadioTapHeader::parse(packet.data) {
                            match dot11::Frame::parse(remaining) {
                                Ok((_remaining, frame)) => write_packet(&mut writer, &frame, opts)?,
                                _ => {}
                            }
                        }
                    }
                    _ => panic!("Unsupported interface: {:?}", link_type),
                }
            }
            Err(e) => {
                panic!("An error occurred while reading packet: {}", e);
            }
        }
        writer.flush()?;
    }
}
