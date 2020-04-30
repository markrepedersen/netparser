use crate::{arp, ipv4, ipv6, parse};

use derive_try_from_primitive::*;
use nom::{bytes::complete::take, combinator::map, error::context, number::complete::be_u16};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Addr(pub [u8; 6]);

impl fmt::Display for Addr {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(
            w,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            a, b, c, d, e, f
        )
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Addr {
    pub fn new(slice: &[u8]) -> Self {
        let mut res = Self([0u8; 6]);
        res.0.copy_from_slice(&slice[..6]);
        res
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("MAC address", map(take(6_usize), Self::new))(i)
    }
}

pub trait DatalinkFrame: Sized + Serialize + Debug {
    fn get_payload(&self) -> &Option<Payload>;

    fn parse(i: parse::Input) -> parse::Result<Self>;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Payload {
    IPv4(ipv4::Packet),
    IPv6(ipv6::Packet),
    ARP(arp::Packet),
    Protected,
    Unknown,
}

#[derive(TryFromPrimitive, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[repr(u16)]
pub enum EtherType {
    IPv4 = 0x0800,
    IPv6 = 0x86dd,
    ARP = 0x0806,
}

impl EtherType {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        context("EtherType", map(be_u16, Self::try_from))(i)
    }
}
