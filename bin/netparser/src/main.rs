use clap::Clap;
use netparse::{run, PacketOptions};

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

fn main() {
    let cli: CLI = CLI::parse();
    let opts = PacketOptions {
        interface: cli.interface,
        udp: cli.udp,
        tcp: cli.tcp,
        icmp: cli.icmp,
        arp: cli.arp,
        ipv4: cli.ipv4,
        ipv6: cli.ipv6,
    };
    
    run(opts);
}
