use crossbeam::{
    self,
    channel::{Receiver, Sender},
    crossbeam_channel::{bounded, tick},
    thread::scope,
};
use datalink::Payload;
use netparse::{
    layer2::{
        arp, datalink, ethernet,
        wifi::{dot11, radiotap},
    },
    layer3::ip::{ip, ipv4},
};
use pcap;
use std::{
    default::Default,
    io::{self, stdin, stdout},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use termion::{
    event::Key, input::MouseTerminal, input::TermRead, raw::IntoRawMode, screen::AlternateScreen,
};
use tui::{
    backend::{Backend, TermionBackend},
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Row, Table, TableState},
    Terminal,
};

pub enum Event {
    Key,
    Tick,
    Paused,
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
    pub fn create_capture() -> Self {
        Self {
            ..Default::default()
        }
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

    pub fn draw<B: Backend>(
        terminal: &mut Terminal<B>,
        table: &Arc<Mutex<StatefulTable>>,
    ) -> Result<(), io::Error> {
        terminal.draw(|mut f| {
            if let Ok(mut data) = table.lock() {
                let selected_style = Style::default()
                    .fg(Color::White)
                    .modifier(Modifier::BOLD | Modifier::ITALIC);
                let normal_style = Style::default().fg(Color::Blue).modifier(Modifier::ITALIC);
                let headers = data.headers.clone();
                let records = data.records.clone();
                let widths = data.widths.clone();
                let rows = records
                    .iter()
                    .map(|i| Row::StyledData(i.into_iter(), normal_style));
                let t = Table::new(headers.into_iter(), rows)
                    .block(
                        Block::default()
                            .title("Packets")
                            .title_style(
                                Style::default()
                                    .fg(Color::DarkGray)
                                    .modifier(Modifier::BOLD),
                            )
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded),
                    )
                    .header_style(
                        Style::default()
                            .fg(Color::DarkGray)
                            .modifier(Modifier::BOLD | Modifier::ITALIC),
                    )
                    .widths(&widths[..])
                    .highlight_style(selected_style)
                    .column_spacing(5)
                    .highlight_symbol(">> ");

                if records.len() > 0 {
                    f.render_stateful_widget(t, f.size(), &mut data.state);
                }
            }
        })?;

        Ok(())
    }

    fn capture_arp_frame(table: &mut MutexGuard<StatefulTable>, frame: &arp::Packet, count: usize) {
        table.push(
            frame.sender_hw_addr.to_string(),
            "SENDER_HW_SRC".to_string(),
            Constraint::Percentage(10),
            count,
        );
        table.push(
            frame.target_hw_addr.to_string(),
            "SENDER_HW_DST".to_string(),
            Constraint::Percentage(10),
            count,
        );
        table.push(
            frame.sender_ip_addr.to_string(),
            "SENDER_IP_SRC".to_string(),
            Constraint::Percentage(10),
            count,
        );
        table.push(
            frame.target_ip_addr.to_string(),
            "TARGET_IP_DST".to_string(),
            Constraint::Percentage(10),
            count,
        );
    }

    fn capture_ip_packet(
        table: &mut MutexGuard<StatefulTable>,
        packet: &ipv4::Packet,
        count: usize,
    ) {
        if let Some(ref proto) = packet.protocol {
            table.push(
                format!("{:?}", proto),
                "TRANSPORT".to_string(),
                Constraint::Percentage(5),
                count,
            );
        }

        table.push(
            packet.dst.to_string(),
            "IP_SRC".to_string(),
            Constraint::Percentage(10),
            count,
        );

        table.push(
            packet.dst.to_string(),
            "IP_DST".to_string(),
            Constraint::Percentage(10),
            count,
        );

        if let ip::Payload::TCP(ref packet) = packet.payload {
            table.push(
                packet.src_port.to_string(),
                "SRC_PORT".to_string(),
                Constraint::Percentage(5),
                count,
            );
            table.push(
                packet.dst_port.to_string(),
                "DST_PORT".to_string(),
                Constraint::Percentage(5),
                count,
            );
        } else if let ip::Payload::UDP(ref packet) = packet.payload {
            table.push(
                packet.src_port.to_string(),
                "SRC_PORT".to_string(),
                Constraint::Percentage(5),
                count,
            );
            table.push(
                packet.dst_port.to_string(),
                "DST_PORT".to_string(),
                Constraint::Percentage(5),
                count,
            );
        }
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
        let link_type = cap.get_datalink();
        cap.filter(filters.as_str())
            .expect("Invalid filter provided");

        while let Ok(packet) = cap.next() {
            if let Ok(Event::Disconnected) = receiver.try_recv() {
                break;
            }

            if let Ok(mut table) = table.lock() {
                table.push(
                    index.to_string(),
                    "NUM".to_string(),
                    Constraint::Percentage(5),
                    index,
                );
            }

            match link_type {
                pcap::Linktype(1) => {
                    if let Ok((_, frame)) = ethernet::Frame::parse(packet.data) {
                        if let Ok(mut table) = table.lock() {
                            if let Some(Payload::IPv4(ref packet)) = frame.payload {
                                if let Some(ref ether_type) = frame.ether_type {
                                    table.push(
                                        format!("{:?}", ether_type),
                                        "ETHERTYPE".to_string(),
                                        Constraint::Percentage(5),
                                        index,
                                    );
                                }
                                Self::capture_ip_packet(&mut table, &packet, index);
                            }
                        }
                    }
                }

                pcap::Linktype(105) => if let Ok((_, frame)) = dot11::Frame::parse(packet.data) {},

                pcap::Linktype(127) => {
                    if let Ok((r, _)) = radiotap::RadioTapHeader::parse(packet.data) {
                        if let Ok((_, frame)) = dot11::Frame::parse(r) {}
                    }
                }

                _ => unimplemented!("Unsupported interface: {:?}", link_type),
            };
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

    fn draw_loop(
        table: &Arc<Mutex<StatefulTable>>,
        receiver: &Receiver<Event>,
    ) -> Result<(), io::Error> {
        let stdout = stdout().into_raw_mode()?;
        let stdout = MouseTerminal::from(stdout);
        let stdout = AlternateScreen::from(stdout);
        let backend = TermionBackend::new(stdout);
        let mut terminal = {
            let mut terminal = Terminal::new(backend)?;
            terminal.hide_cursor()?;
            terminal
        };

        Self::draw(&mut terminal, &table)?;

        loop {
            match receiver.recv() {
                Ok(Event::Disconnected) => {
                    terminal.clear()?;
                    std::process::exit(0);
                }
                Ok(Event::Key) | Ok(Event::Tick) => Self::draw(&mut terminal, &table)?,
                _ => {}
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
            scope.spawn(|_| Self::draw_loop(&table, &receiver));
        })
        .unwrap();

        Ok(())
    }
}

#[allow(dead_code)]
pub struct StatefulTable {
    state: TableState,
    headers: Vec<String>,
    widths: Vec<Constraint>,
    records: Vec<Vec<String>>,
}

impl StatefulTable {
    fn new() -> StatefulTable {
        StatefulTable {
            state: TableState::default(),
            headers: vec![],
            widths: vec![],
            records: vec![],
        }
    }

    pub fn push(&mut self, item: String, header: String, width: Constraint, index: usize) {
        if let Some(rec) = self.records.get_mut(index) {
            rec.push(item);
        } else {
            let rec = vec![item];
            self.records.push(rec);
        }
        if !self.headers.contains(&header) {
            self.headers.push(header);
            self.widths.push(width);
        }
    }

    pub fn next(&mut self, long: bool) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.records.len() - 1 {
                    0
                } else {
                    if long {
                        i + 10
                    } else {
                        i + 1
                    }
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self, long: bool) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.records.len() - 1
                } else {
                    if long {
                        i - 10
                    } else {
                        i - 1
                    }
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

pub fn run_app() -> Result<(), io::Error> {
    Capture::create_capture().with_wireless(false).start()
}
