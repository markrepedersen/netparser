mod arp;
mod blob;
mod dot11;
mod frame;
mod icmp;
mod ipv4;
mod ipv6;
mod parse;
mod serialize;
mod tcp;
mod udp;

use clap::Clap;
use pnet::datalink;

#[derive(Clap)]
#[clap(version = "1.0", author = "Mark Pedersen")]
pub struct CLI {
    #[clap(
        short = "i",
        long = "interface",
        value_name = "name",
        takes_value = true,
        default_value = "en0",
        required = true
    )]
    interface: String,
    #[clap(short = "U", long = "udp")]
    udp: bool,
    #[clap(short = "T", long = "tcp")]
    tcp: bool,
    #[clap(short = "I", long = "icmp")]
    icmp: bool,
    #[clap(short = "A", long = "arp")]
    arp: bool,
    #[clap(short = "4", long = "ipv4")]
    ipv4: bool,
    #[clap(short = "6", long = "ipv6")]
    ipv6: bool,
}

#[derive(Debug, Default)]
struct NetworkRecord {
    mac_src: String,
    mac_dst: String,
    ip_src: String,
    ip_dst: String,
}

fn show_ipv4(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

fn show_ipv6(frame: frame::Frame) {
    if let frame::Payload::IPv6(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

fn show_arp(frame: frame::Frame) {
    if let frame::Payload::ARP(ref ip_packet) = frame.payload {
        println!("{:#?}", ip_packet);
    }
}

fn show_tcp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ipv4::Payload::TCP(ref tcp_packet) = ip_packet.payload {
            println!("{:#?}", tcp_packet);
        }
    }
}

fn show_udp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ipv4::Payload::UDP(ref udp_packet) = ip_packet.payload {
            println!("{:#?}", udp_packet);
        }
    }
}

fn show_icmp(frame: frame::Frame) {
    if let frame::Payload::IPv4(ref ip_packet) = frame.payload {
        if let ipv4::Payload::ICMP(ref icmp_packet) = ip_packet.payload {
            println!("{:#?}", icmp_packet);
        }
    }
}

fn main() -> Result<(), std::io::Error> {
    let opts: CLI = CLI::parse();
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == opts.interface)
        .next()
        .unwrap();
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Datalink channel error: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => match frame::Frame::parse(packet) {
                Ok((_remaining, frame)) => match opts {
                    CLI { ipv4: true, .. } => show_ipv4(frame),
                    CLI { ipv6: true, .. } => show_ipv6(frame),
                    CLI { arp: true, .. } => show_arp(frame),
                    CLI { tcp: true, .. } => show_tcp(frame),
                    CLI { udp: true, .. } => show_udp(frame),
                    CLI { icmp: true, .. } => show_icmp(frame),
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
