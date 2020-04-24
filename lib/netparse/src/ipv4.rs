use crate::{
    icmp,
    parse::{self, BitParsable},
    tcp, udp,
};

use custom_debug_derive::*;
use derive_try_from_primitive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};
use std::fmt;
use ux::*;

#[derive(Debug, TryFromPrimitive)]
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

#[derive(Debug)]
pub enum Payload {
    UDP(udp::Datagram),
    TCP(tcp::Packet),
    ICMP(icmp::Packet),
    Unknown,
}

#[derive(CustomDebug)]
pub struct Packet {
    #[debug(format = "{:x}")]
    pub version: u4,
    #[debug(format = "{:x}")]
    pub ihl: u4,
    #[debug(format = "{:x}")]
    pub dscp: u6,
    #[debug(format = "{:b}")]
    pub ecn: u2,
    #[debug(format = "{}")]
    pub length: u16,
    #[debug(format = "{:04x}")]
    pub identification: u16,
    #[debug(format = "{:b}")]
    pub flags: u3,
    #[debug(format = "{}")]
    pub fragment_offset: u13,
    #[debug(format = "{}")]
    pub ttl: u8,
    pub src: Addr,
    pub dst: Addr,
    #[debug(skip)]
    pub checksum: u16,
    pub protocol: Option<Protocol>,
    pub payload: Payload,
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("IPv4 frame", |i| {
            let (i, (version, ihl)) = bits(tuple((u4::parse, u4::parse)))(i)?;
            let (i, (dscp, ecn)) = bits(tuple((u6::parse, u2::parse)))(i)?;
            let (i, length) = be_u16(i)?;
            let (i, identification) = be_u16(i)?;
            let (i, (flags, fragment_offset)) = bits(tuple((u3::parse, u13::parse)))(i)?;
            let (i, ttl) = be_u8(i)?;
            let (i, protocol) = Protocol::parse(i)?;
            let (i, checksum) = be_u16(i)?;
            let (i, (src, dst)) = tuple((Addr::parse, Addr::parse))(i)?;
            let (i, payload) = match protocol {
                Some(Protocol::TCP) => map(tcp::Packet::parse, Payload::TCP)(i)?,
                Some(Protocol::UDP) => map(udp::Datagram::parse, Payload::UDP)(i)?,
                Some(Protocol::ICMP) => map(icmp::Packet::parse, Payload::ICMP)(i)?,
                _ => (i, Payload::Unknown),
            };

            let res = Self {
                version,
                ihl,
                dscp,
                ecn,
                length,
                identification,
                flags,
                fragment_offset,
                ttl,
                protocol,
                checksum,
                src,
                dst,
                payload,
            };
            Ok((i, res))
        })(i)
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Addr(pub [u8; 4]);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, slice) = context("IPv4 address", take(4_usize))(i)?;
        let mut res = Self([0, 0, 0, 0]);
        res.0.copy_from_slice(slice);
        Ok((i, res))
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{}.{}.{}.{}", a, b, c, d)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
