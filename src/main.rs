mod arp;
mod cli;
mod dot11;
mod frame;
mod ipv4;
mod ipv6;
mod parse;
mod serialize;

use cli::CLI;
use frame::Frame;
use pnet::datalink;

#[derive(Debug, Default)]
struct NetworkRecord {
    mac_src: String,
    mac_dst: String,
    ip_src: String,
    ip_dst: String,
}

fn main() {
    let args = CLI::new();
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == args.interface)
        .next()
        .unwrap();
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Datalink channel error: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let mut container: NetworkRecord = NetworkRecord::default();
                let frame: Frame = process_packet(packet);

                println!("{:#?}", frame);

                // match frame.payload {
                //     frame::Payload::IPv4(packet) => {}
                //     frame::Payload::IPv6(packet) => {}
                //     frame::Payload::ARP(packet) => {}
                //     frame::Payload::Unknown => {}
                // }
            }
            Err(e) => {
                panic!("An error occurred while reading packet: {}", e);
            }
        }
    }
}

fn process_packet(packet: &[u8]) -> frame::Frame {
    match frame::Frame::parse(packet) {
        Ok((_remaining, frame)) => {
            return frame;
        }
        Err(nom::Err::Error(e)) => {
            println!("{:?}", e);
            panic!();
        }
        _ => unreachable!(),
    }
}
