use clap::Clap;
use netparse::{run, PacketOptions};

///Specifies output options when parsing packets.
#[derive(Clap)]
#[clap(version = "1.0", author = "Mark Pedersen")]
pub struct CLI {
    #[clap(
        short = "i",
        long = "interface",
        value_name = "name",
        takes_value = true,
        required = true
    )]
    /// Specifies the interface on which to monitor.
    interface: String,
    #[clap(
        short = "f",
        long = "filename",
        value_name = "filename",
        takes_value = true
    )]
    /// Specifies the output file name.
    file_name: Option<String>,
    #[clap(short = "H", long = "hexdump")]
    /// Output as raw hex instead of parsing the various fields.
    hex_dump: bool,
    #[clap(short = "j", long = "json")]
    /// Output as JSON. This will only work if a file name is also provided.
    json: bool,
    /// On most OSes, 802.11 frames are converted into fake Ethernet frames, unless monitor mode is being used.
    /// This option will use monitor mode so the raw, wireless frames are displayed instead.
    #[clap(short = "W", long = "wireless")]
    wireless: bool,
    #[clap(long = "filter", takes_value = true)]
    /// Filter by pcap filter. See https://biot.com/capstats/bpf.html for syntax.
    filter: Option<String>,
    #[clap(short = "U", long = "udp")]
    /// Output only UDP packets.
    udp: bool,
    #[clap(short = "T", long = "tcp")]
    /// Output only TCP packets.
    tcp: bool,
    #[clap(short = "I", long = "icmp")]
    /// Output only ICMP packets.
    icmp: bool,
    #[clap(short = "A", long = "arp")]
    /// Output only ARP packets.
    arp: bool,
    #[clap(short = "4", long = "ipv4")]
    /// Output only IPv4 packets.
    ipv4: bool,
    #[clap(short = "6", long = "ipv6")]
    /// Output only IPv6 packets.
    ipv6: bool,
}

fn main() {
    let cli: CLI = CLI::parse();
    let opts = PacketOptions {
        interface: cli.interface,
        hex_dump: cli.hex_dump,
        json: cli.json,
        file_name: cli.file_name,
        wireless: cli.wireless,
        filter: cli.filter,
        udp: cli.udp,
        tcp: cli.tcp,
        icmp: cli.icmp,
        arp: cli.arp,
        ipv4: cli.ipv4,
        ipv6: cli.ipv6,
    };

    run(&opts).expect("There was a problem parsing a packet(s)");
}
