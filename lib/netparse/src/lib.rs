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
