use clap::{App, Arg};
use custom_debug_derive::*;

#[derive(CustomDebug)]
pub struct CLI {
    pub interface: String,
}

impl CLI {
    pub fn new() -> Self {
        let matches = App::new("rust_wifi_deauther")
            .version("1.0")
            .author("Mark Pedersen <markrepedersen@gmail.com>")
            .about("Send deauth frames to all devices on subnet.")
            .arg(Arg::with_name("interface")
		 .short("i")
		 .long("interface")
		 .value_name("name")
		 .help("The name of the wireless network interface. On MacOS, the wifi interface is 'en0'.")
		 .takes_value(true)
		 .default_value("en0")
		 .required(true))
	    .arg(Arg::with_name("verbose")
		 .short("v")
		 .long("verbose")
		 .help("Enable verbose mode."))
	    .get_matches();
        let interface = matches
            .value_of("interface")
            .expect("Network interface parameter is required.");
        CLI {
            interface: String::from(interface),
        }
    }
}
