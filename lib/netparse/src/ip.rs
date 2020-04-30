use crate::{icmp, parse, tcp, udp};

use derive_try_from_primitive::*;
use nom::{combinator::map, error::context, number::complete::be_u8};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub enum Payload {
    UDP(udp::Datagram),
    TCP(tcp::Packet),
    ICMP(icmp::Packet),
    Unknown,
}

#[derive(Debug, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u8)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl Protocol {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        context("IPv4 Protocol", map(be_u8, Self::try_from))(i)
    }
}
