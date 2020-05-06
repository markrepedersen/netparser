#![feature(arbitrary_enum_discriminant)]

pub mod layer2 {
    pub mod arp;
    pub mod wifi {
        pub mod data;
        pub mod dot11;
        pub mod management;
        pub mod radiotap;
    }
    pub mod datalink;
    pub mod ethernet;
}

pub mod layer3 {
    pub mod icmp;
    pub mod ip {
        pub mod ip;
        pub mod ipv4;
        pub mod ipv6;
        pub mod tcp;
        pub mod udp;
    }
}

pub mod core {
    pub mod blob;
    pub mod hex_slice;
    pub mod parse;
    pub mod ux;
}

use crate::core::hex_slice::HexSlice;
use crate::core::parse;
use crate::layer2::{
    datalink, ethernet,
    wifi::{dot11, radiotap},
};
use crate::layer3::ip::ip;

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
    pub filter: Option<String>,
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
fn write_packet<T: Write>(
    i: parse::Input,
    mut writer: &mut T,
    opts: &PacketOptions,
) -> Result<(), Box<dyn Error>> {
    if opts.wireless {
        if let Ok((_, frame)) = dot11::Frame::parse(i) {
            write(&mut writer, &frame, opts.json)?
        }
    } else {
        if let Ok((_, frame)) = ethernet::Frame::parse(i) {
            let mut verbose = true;

            if opts.ipv4 {
                verbose = false;
                if let Some(datalink::Payload::IPv4(ref ip_packet)) = frame.payload {
                    write(&mut writer, &ip_packet, opts.json)?;
                }
            }

            if opts.ipv6 {
                verbose = false;
                if let Some(datalink::Payload::IPv6(ref ip_packet)) = frame.payload {
                    write(&mut writer, &ip_packet, opts.json)?;
                }
            }

            if opts.arp {
                verbose = false;
                if let Some(datalink::Payload::ARP(ref arp_packet)) = frame.payload {
                    write(&mut writer, &arp_packet, opts.json)?;
                }
            }

            if opts.tcp {
                verbose = false;
                match frame.payload {
                    Some(datalink::Payload::IPv4(ref ip_packet)) => {
                        if let ip::Payload::TCP(ref udp_packet) = ip_packet.payload {
                            write(&mut writer, &udp_packet, opts.json)?;
                        }
                    }

                    Some(datalink::Payload::IPv6(ref ip_packet)) => {
                        if let ip::Payload::TCP(ref udp_packet) = ip_packet.payload {
                            write(&mut writer, &udp_packet, opts.json)?;
                        }
                    }
                    _ => {}
                }
            }

            if opts.udp {
                verbose = false;
                match frame.payload {
                    Some(datalink::Payload::IPv4(ref ip_packet)) => {
                        if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
                            write(&mut writer, &udp_packet, opts.json)?;
                        }
                    }

                    Some(datalink::Payload::IPv6(ref ip_packet)) => {
                        if let ip::Payload::UDP(ref udp_packet) = ip_packet.payload {
                            write(&mut writer, &udp_packet, opts.json)?;
                        }
                    }
                    _ => {}
                }
            }

            if opts.icmp {
                verbose = false;
                match frame.payload {
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
                write(&mut writer, &frame, opts.json)?;
            }
        }
    }
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
        .buffer_size(512)
        .open()
        .unwrap();
    let link_type = cap.get_datalink();
    let mut writer = create_writer(opts);

    if opts.filter.is_some() {
        cap.filter(opts.filter.clone().unwrap().as_str())
            .expect("Invalid filter provided");
    }

    println!("Capturing packets from interface '{}'.", opts.interface);

    loop {
        match cap.next() {
            Ok(packet) => {
                // if opts.hex_dump {
                writeln!(&mut writer, "{:X}", HexSlice::new(packet.data))?;
                writeln!(&mut writer)?;
                // }

                match link_type {
                    Linktype(1) | Linktype(105) => write_packet(packet.data, &mut writer, opts)?,
                    Linktype(127) => {
                        if let Ok((remaining, _)) = radiotap::RadioTapHeader::parse(packet.data) {
                            write_packet(remaining, &mut writer, opts)?;
                        }
                    }
                    _ => unimplemented!("Unsupported interface: {:?}", link_type),
                }

                writer.flush()?;
            }
            Err(e) => {
                panic!("An error occurred while reading packet: {}", e);
            }
        }
    }
}
