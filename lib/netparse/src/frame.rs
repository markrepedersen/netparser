use crate::{arp, ipv4, ipv6, parse};

use custom_debug_derive::*;
use derive_try_from_primitive::*;
use nom::{
    bytes::complete::take, combinator::map, error::context, number::complete::be_u16,
    sequence::tuple,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Addr(pub [u8; 6]);

impl fmt::Display for Addr {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(
            w,
            "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
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

#[derive(Debug, Serialize, Deserialize)]
pub enum Payload {
    IPv4(ipv4::Packet),
    IPv6(ipv6::Packet),
    ARP(arp::Packet),
    Unknown,
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Frame {
    pub dst: Addr,
    pub src: Addr,
    pub payload: Payload,
    pub ether_type: Option<EtherType>,
}

impl Frame {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("Ethernet frame", |i| {
            let (i, (dst, src)) = tuple((Addr::parse, Addr::parse))(i)?;
            let (i, ether_type) = EtherType::parse(i)?;
            let (i, payload) = match ether_type {
                Some(EtherType::IPv4) => map(ipv4::Packet::parse, Payload::IPv4)(i)?,
                Some(EtherType::IPv6) => map(ipv6::Packet::parse, Payload::IPv6)(i)?,
                Some(EtherType::ARP) => map(arp::Packet::parse, Payload::ARP)(i)?,
                None => (i, Payload::Unknown),
            };

            let res = Self {
                dst,
                src,
                ether_type,
                payload,
            };
            Ok((i, res))
        })(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FRAME: &[u8] = &[
        0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB, 0x58, 0x00, 0xE3, 0x1D, 0x1E, 0x6B, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3D, 0x62, 0xB8, 0x00, 0x00, 0x01, 0x11, 0xB4, 0x11, 0xC0, 0xA8, 0x01, 0x43,
        0xE0, 0x00, 0x00, 0xFB, 0x14, 0xE9, 0x14, 0xE9, 0x00, 0x29, 0xAE, 0x6D, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5F, 0x69, 0x70, 0x70, 0x04,
        0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, 0x00, 0x0C, 0x80, 0x01,
    ];

    #[test]
    fn assert_valid_frame() {
        let frame = Frame::parse(TEST_FRAME).unwrap().1;
        let dst_addr = Addr::new(&TEST_FRAME[..6]);
        let src_addr = Addr::new(&TEST_FRAME[6..12]);

        assert_eq!(frame.dst, dst_addr);
        assert_eq!(frame.src, src_addr);
        assert_eq!(frame.ether_type.unwrap(), EtherType::IPv4);
    }

    #[test]
    #[should_panic]
    fn assert_invalid_frame() {
        let frame_len = TEST_FRAME.len();
        Frame::parse(&TEST_FRAME[frame_len - 4..frame_len - 1])
            .unwrap()
            .1;
    }
}
