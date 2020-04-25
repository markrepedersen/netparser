use crate::{
    icmp,
    ip::{Payload, Protocol},
    parse,
    parse::BitParsable,
    tcp, udp,
    ux::*,
};

use custom_debug_derive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Default)]
pub struct Addr(pub [u8; 16]);

impl fmt::Display for Addr {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let ipv6 = &self.0;
        let ipv6_len = ipv6.len();
        let mut res = String::new();

        for (i, byte) in ipv6.iter().enumerate() {
            if i % 2 == 0 || i == ipv6_len - 1 {
                res.push_str(&format!("{:02X}", byte));
            } else {
                res.push_str(&format!("{:02X}:", byte));
            }
        }
        write!(w, "{}", res)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, slice) = context("IPv6 address", take(16_usize))(i)?;
        let mut res = Self::default();
        res.0.copy_from_slice(slice);
        Ok((i, res))
    }
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Packet {
    #[debug(format = "{:02X}")]
    pub version: u4,
    #[debug(format = "{:02X}")]
    pub traffic_class: u8,
    #[debug(format = "{:02X}")]
    pub flow_label: u20,
    #[debug(format = "{}")]
    pub payload_len: u16,
    pub protocol: Option<Protocol>,
    #[debug(format = "{}")]
    pub ttl: u8,
    pub src: Addr,
    pub dst: Addr,
    pub payload: Payload,
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("IPv6 frame", |i| {
            let (i, (version, traffic_class, flow_label)) =
                bits(tuple((u4::parse, u8::parse, u20::parse)))(i)?;
            let (i, payload_len) = be_u16(i)?;
            let (i, protocol) = Protocol::parse(i)?;
            let (i, ttl) = be_u8(i)?;
            let (i, src) = Addr::parse(i)?;
            let (i, dst) = Addr::parse(i)?;
            let (i, payload) = match protocol {
                Some(Protocol::TCP) => map(tcp::Packet::parse, Payload::TCP)(i)?,
                Some(Protocol::UDP) => map(udp::Datagram::parse, Payload::UDP)(i)?,
                Some(Protocol::ICMP) => map(icmp::Packet::parse, Payload::ICMP)(i)?,
                _ => (i, Payload::Unknown),
            };
            let res = Self {
                version,
                traffic_class,
                flow_label,
                payload_len,
                protocol,
                ttl,
                src,
                dst,
                payload,
            };

            Ok((i, res))
        })(i)
    }
}
