use crate::draw::*;
use crate::table::*;
use crossbeam::{
    self,
    channel::{Receiver, Sender},
    crossbeam_channel::{bounded, tick},
    thread::scope,
};
use datalink::Payload;
use netparse::{
    layer2::{
        datalink::{self, Frame},
        ethernet,
        wifi::{dot11, radiotap},
    },
    layer3::ip::{ip, ipv4, ipv6, tcp, udp},
};
use pcap::{self, Linktype};
use std::{
    default::Default,
    io::{self, stdin},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use termion::{event::Key, input::TermRead};
use tui::layout::Constraint;

pub enum Event {
    Key,
    Tick,
    Paused,
    Selected,
    Disconnected,
}

pub struct Capture {
    interface: String,
    wireless: bool,
    monitor: bool,
    filter: String,
}

impl Default for Capture {
    fn default() -> Self {
        let interface = if cfg!(target_os = "linux") {
            "eth0"
        } else if cfg!(target_os = "windows") {
            "Ethernet"
        } else if cfg!(target_os = "macos") {
            "en0"
        } else {
            panic!("Target OS not supported.");
        }
        .to_string();
        Self {
            interface,
            wireless: false,
            monitor: false,
            filter: String::new(),
        }
    }
}

impl Capture {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    #[allow(dead_code)]
    pub fn with_interface(&mut self, interface: String) -> &Self {
        self.interface = interface;
        self
    }

    #[allow(dead_code)]
    pub fn with_wireless(&mut self, wireless: bool) -> &Self {
        self.wireless = wireless;
        self.monitor = wireless;
        self
    }

    #[allow(dead_code)]
    pub fn with_filter(&mut self, filter: String) -> &Self {
        self.filter = filter;
        self
    }

    fn add(
        table: &mut MutexGuard<StatefulTable>,
        field: String,
        header: String,
        len: u16,
        index: usize,
    ) {
        table.push(field, header, Constraint::Percentage(len), index);
    }

    fn capture_tcp_packet(
        table: &mut MutexGuard<StatefulTable>,
        packet: &tcp::Packet,
        index: usize,
    ) {
        Self::add(
            table,
            packet.src_port.to_string(),
            "SRC_PORT".to_string(),
            5,
            index,
        );
        Self::add(
            table,
            packet.dst_port.to_string(),
            "DST_PORT".to_string(),
            5,
            index,
        );
    }

    fn capture_udp_packet(
        table: &mut MutexGuard<StatefulTable>,
        packet: &udp::Datagram,
        index: usize,
    ) {
        Self::add(
            table,
            packet.src_port.to_string(),
            "SRC_PORT".to_string(),
            5,
            index,
        );
        Self::add(
            table,
            packet.dst_port.to_string(),
            "DST_PORT".to_string(),
            5,
            index,
        );
    }

    fn capture_ipv4_packet(
        table: &mut MutexGuard<StatefulTable>,
        packet: &ipv4::Packet,
        index: usize,
    ) {
        if let Some(ref proto) = packet.protocol {
            Self::add(table, format!("{:?}", proto), "L4".to_string(), 5, index);
        }

        Self::add(
            table,
            packet.src.to_string(),
            "IP_SRC".to_string(),
            24,
            index,
        );
        Self::add(
            table,
            packet.dst.to_string(),
            "IP_DST".to_string(),
            24,
            index,
        );
        if let ip::Payload::TCP(ref packet) = packet.payload {
            Self::capture_tcp_packet(table, &packet, index);
        } else if let ip::Payload::UDP(ref packet) = packet.payload {
            Self::capture_udp_packet(table, &packet, index);
        }
    }

    fn capture_ipv6_packet(
        table: &mut MutexGuard<StatefulTable>,
        packet: &ipv6::Packet,
        index: usize,
    ) {
        if let Some(ref proto) = packet.protocol {
            Self::add(table, format!("{:?}", proto), "L4".to_string(), 5, index);
        }

        Self::add(
            table,
            packet.src.to_string(),
            "IP_SRC".to_string(),
            24,
            index,
        );
        Self::add(
            table,
            packet.dst.to_string(),
            "IP_DST".to_string(),
            24,
            index,
        );
        if let ip::Payload::TCP(ref packet) = packet.payload {
            Self::capture_tcp_packet(table, &packet, index);
        } else if let ip::Payload::UDP(ref packet) = packet.payload {
            Self::capture_udp_packet(table, &packet, index);
        }
    }

    fn capture_payload(
        table: &mut MutexGuard<StatefulTable>,
        payload: &Option<Payload>,
        index: usize,
    ) {
        match payload {
            Some(Payload::IPv4(ref packet)) => Self::capture_ipv4_packet(table, packet, index),
            Some(Payload::IPv6(ref packet)) => Self::capture_ipv6_packet(table, packet, index),
            _ => {}
        };
    }

    fn capture_dot11_addr(
        table: &mut MutexGuard<StatefulTable>,
        addr: &dot11::Dot11Addr,
        index: usize,
    ) {
        use dot11::Dot11Addr::*;
        match addr {
            BSSID(addr) => Self::add(table, addr.to_string(), "BSSID".to_string(), 12, index),
            SourceAddress(addr) => {
                Self::add(table, addr.to_string(), "BSSID".to_string(), 12, index)
            }
            DestinationAddress(addr) => {
                Self::add(table, addr.to_string(), "DST_ADDR".to_string(), 12, index)
            }
            ReceiverAddress(addr) => {
                Self::add(table, addr.to_string(), "RECV_ADDR".to_string(), 12, index)
            }
            TransmitterAddress(addr) => {
                Self::add(table, addr.to_string(), "TRM_ADDR".to_string(), 12, index)
            }
        }
    }

    fn capture_dot11_frame(
        table: &mut MutexGuard<StatefulTable>,
        frame: &dot11::Frame,
        index: usize,
    ) {
        Self::capture_dot11_addr(table, &frame.addr1, index);
        if let Some(ref addr) = frame.addr2 {
            Self::capture_dot11_addr(table, &addr, index);
        }
        if let Some(ref addr) = frame.addr3 {
            Self::capture_dot11_addr(table, &addr, index);
        }
        if let Some(ref addr) = frame.addr4 {
            Self::capture_dot11_addr(table, &addr, index);
        }
    }

    fn capture_frame(table: &mut MutexGuard<StatefulTable>, frame: &Frame, index: usize) {
        table.push(
            index.to_string(),
            "N".to_string(),
            Constraint::Percentage(5),
            index,
        );

        match frame {
            Frame::Ethernet(ref frame) => {
                if let Some(ref ether_type) = frame.ether_type {
                    Self::add(
                        table,
                        format!("{:?}", ether_type),
                        "L3".to_string(),
                        5,
                        index,
                    );
                }

                Self::capture_payload(table, &frame.payload, index);
            }

            Frame::Dot11(ref frame) => Self::capture_dot11_frame(table, frame, index),
        };
    }

    fn capture_packets(&self, table: &Arc<Mutex<StatefulTable>>, receiver: &Receiver<Event>) {
        let monitor = self.monitor;
        let interface = self.interface.clone();
        let filters = self.filter.clone();
        let mut index = 0;
        let mut cap = pcap::Capture::from_device(interface.as_str())
            .expect("There was a problem selecting the given interface.")
            .promisc(true)
            .rfmon(monitor)
            .buffer_size(512)
            .open()
            .expect("There was a problem capturing on that interface.");
        cap.filter(filters.as_str())
            .expect("Invalid filter provided");

        let link_type = cap.get_datalink();

        while let Ok(packet) = cap.next() {
            if let Ok(Event::Disconnected) = receiver.try_recv() {
                break;
            }

            if let Ok(mut table) = table.lock() {
                match link_type {
                    Linktype(1) => {
                        if let Ok((_, frame)) = ethernet::Frame::parse(packet.data) {
                            let frame = Frame::Ethernet(frame);
                            Self::capture_frame(&mut table, &frame, index);
                            table.frames.push(frame);
                        }
                    }

                    Linktype(105) => {
                        if let Ok((_, frame)) = dot11::Frame::parse(packet.data) {
                            let frame = Frame::Dot11(frame);
                            Self::capture_frame(&mut table, &frame, index);
                            table.frames.push(frame);
                        }
                    }

                    Linktype(127) => {
                        if let Ok((remaining, _)) = radiotap::RadioTapHeader::parse(packet.data) {
                            if let Ok((_, frame)) = dot11::Frame::parse(remaining) {
                                let frame = Frame::Dot11(frame);
                                Self::capture_frame(&mut table, &frame, index);
                                table.frames.push(frame);
                            }
                        }
                    }

                    _ => unimplemented!("Unsupported interface: {:?}", link_type),
                };
            }
            index = index + 1;
        }
    }

    fn receive_key(
        table: &Arc<Mutex<StatefulTable>>,
        sender: &Sender<Event>,
        receiver: &Receiver<Event>,
    ) {
        loop {
            if let Ok(Event::Disconnected) = receiver.try_recv() {
                break;
            }

            let stdin = stdin();
            for evt in stdin.keys() {
                match evt {
                    Ok(key) => {
                        if let Ok(mut data) = table.lock() {
                            match key {
                                Key::Char('q') => sender.send(Event::Disconnected).unwrap_or(()),
                                Key::Char(' ') => sender.send(Event::Paused).unwrap_or(()),
                                Key::Char('h') => sender.send(Event::Selected).unwrap_or(()),
                                Key::Down => data.next(false),
                                Key::Ctrl(key) if key == 'n' => data.next(false),
                                Key::Ctrl(key) if key == 'p' => data.previous(false),
                                Key::Ctrl(key) if key == 'v' => data.next(true),
                                Key::Alt(key) if key == 'v' => data.previous(true),
                                Key::Up => data.previous(false),
                                _ => {}
                            };
                            sender.send(Event::Key).unwrap_or(());
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    fn tick(sender: &Sender<Event>) {
        let ticket = tick(Duration::from_secs_f64(0.5));
        loop {
            match ticket.recv() {
                Ok(_) => {
                    sender.send(Event::Tick).unwrap_or(());
                }
                Err(_) => {}
            }
        }
    }

    pub fn start(&self) -> Result<(), io::Error> {
        let table = Arc::new(Mutex::new(StatefulTable::new()));
        let (sender, receiver) = bounded::<Event>(5);

        scope(|scope| {
            scope.spawn(|_| self.capture_packets(&table, &receiver));
            scope.spawn(|_| Self::receive_key(&table, &sender, &receiver));
            scope.spawn(|_| Self::tick(&sender));
            scope.spawn(|_| draw(&table, &receiver));
        })
        .unwrap();

        Ok(())
    }
}
