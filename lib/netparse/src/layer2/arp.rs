use crate::{core::parse, layer2::datalink::*, layer3::ip::ipv4};

use custom_debug_derive::*;
use derive_try_from_primitive::*;
use nom::{
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum Operation {
    ARPRequest = 1,
    ARPReply,
    RARPRequest,
    RARPReply,
    DRARPRequest,
    DRARPReply,
    DRARPError,
    InARPRequest,
    InARPReply,
}

impl Operation {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Option<Self>> {
        context("Operation", map(be_u16, Self::try_from))(i)
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum HardwareType {
    Ethernet = 1,
    IEEE_802_Networks = 6,
    ARCNET,
    FrameRelay = 15,
    AsyncTransferMode1,
    HDLC,
    FibreChannel,
    AsyncTransferMode2,
    SerialLine,
}

impl HardwareType {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Option<Self>> {
        context("HardwareType", map(be_u16, Self::try_from))(i)
    }
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Packet {
    pub htype: Option<HardwareType>,
    pub ptype: Option<EtherType>,
    #[debug(format = "{}")]
    pub hlen: u8,
    #[debug(format = "{}")]
    pub plen: u8,
    pub operation: Option<Operation>,
    pub sender_hw_addr: Addr,
    pub sender_ip_addr: ipv4::Addr,
    pub target_hw_addr: Addr,
    pub target_ip_addr: ipv4::Addr,
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("ARP Frame", |i| {
            let (i, (htype, ptype, hlen, plen)) =
                tuple((HardwareType::parse, EtherType::parse, be_u8, be_u8))(i)?;

            let (i, operation) = Operation::parse(i)?;

            let (i, (sender_hw_addr, sender_ip_addr)) = tuple((Addr::parse, ipv4::Addr::parse))(i)?;

            let (i, (target_hw_addr, target_ip_addr)) = tuple((Addr::parse, ipv4::Addr::parse))(i)?;

            let res = Self {
                htype,
                ptype,
                hlen,
                plen,
                operation,
                sender_hw_addr,
                sender_ip_addr,
                target_hw_addr,
                target_ip_addr,
            };
            Ok((i, res))
        })(i)
    }
}
