use crate::{
    arp,
    datalink::*,
    ipv4, ipv6,
    parse::{self, BitParsable},
    ux::*,
};

use custom_debug_derive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u8, le_u16, le_u32, le_u8},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};

#[derive(CustomDebug, Serialize, Deserialize)]
pub enum Type {
    Management = 0x0,
    Control,
    Data,
    Extension,
}

#[allow(non_camel_case_types)]
#[derive(CustomDebug, Serialize, Deserialize)]
pub enum SubType {
    AssociationRequest = 0x0,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisement,
    Reserved1,
    Beacon,
    ATIM,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    NACK,
    Reserved2,
    Reserved3,
    Trigger,
    BeamformingReportPoll,
    VHT_OR_HE_NDP_Announcement,
    ControlFrameExtension,
    ControlWrapper,
    BAR,
    BA,
    PSPoll,
    RTS,
    CTS,
    ACK,
    CFEnd,
    CFEnd_And_CFAck,
    Data,
    Data_And_CFAck,
    Data_And_CFPoll,
    Data_And_CFAck_And_CFPoll,
    Null,
    CFAck_NoData,
    CFPoll_NoData,
    CFAck_And_CFPoll_NoData,
    QoSData,
    QoSData_And_CFAck,
    QoSData_And_CFPoll,
    QoSData_And_CFAck_And_CFPoll,
    QoSNull,
    Reserved4,
    QoS_CFPoll,
    QoS_CFAck_And_CFPoll,
    DMGBeacon,
    Reserved5,
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct FrameControl {
    #[debug(format = "{}")]
    pub version: u2,

    #[debug(format = "{}")]
    pub typ: u2,

    #[debug(format = "{}")]
    pub subtype: u4,

    #[debug(format = "{}")]
    pub to_ds: u1,

    #[debug(format = "{}")]
    pub from_ds: u1,

    #[debug(format = "{}")]
    pub more_fragments: u1,

    #[debug(format = "{}")]
    pub retry: u1,

    #[debug(format = "{}")]
    pub power_mgmt: u1,

    #[debug(format = "{}")]
    pub more_data: u1,

    #[debug(format = "{}")]
    pub wep: u1,

    #[debug(format = "{}")]
    pub order: u1,
}

impl FrameControl {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Frame Control", |i| {
            let (i, (version, typ, subtype)) = bits(tuple((u2::parse, u2::parse, u4::parse)))(i)?;
            let (i, (to_ds, from_ds, more_fragments, retry, power_mgmt, more_data, wep, order)) =
                bits(tuple((
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                )))(i)?;
            let res = Self {
                version,
                typ,
                subtype,
                to_ds,
                from_ds,
                more_fragments,
                retry,
                power_mgmt,
                more_data,
                wep,
                order,
            };
            return Ok((i, res));
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct RadioTapHeader {
    #[debug(format = "{:02X}")]
    pub it_version: u8,
    #[debug(format = "{}")]
    pub it_pad: u8,
    #[debug(format = "{}")]
    pub it_len: u16,
    #[debug(format = "{:08X}")]
    pub it_present: u32,
}

impl RadioTapHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Radiotap Header", |i| {
            let original_i = i;
            let (i, it_version) = le_u8(i)?;
            let (i, it_pad) = le_u8(i)?;
            let (i, it_len) = le_u16(i)?;
            let (_, it_present) = le_u32(i)?;
            let (i, _) = take(it_len)(original_i)?;

            let res = Self {
                it_version,
                it_pad,
                it_len,
                it_present,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct LLCHeader {
    #[debug(format = "{:02X}")]
    pub dsap: u8,
    #[debug(format = "{:02X}")]
    pub ssap: u8,
    #[debug(format = "{:02X}")]
    pub ctrl: u8,
}

impl LLCHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 LLC Header", |i| {
            let (i, dsap) = be_u8(i)?;
            let (i, ssap) = be_u8(i)?;
            let (i, ctrl) = be_u8(i)?;

            let res = Self { dsap, ssap, ctrl };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SNAPHeader {
    pub ether_type: Option<EtherType>,
}

impl SNAPHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 SNAP Header", |i| {
            let (i, _) = take(3_usize)(i)?;
            let (i, ether_type) = EtherType::parse(i)?;

            let res = Self { ether_type };
            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
/// The MAC Frame header. LLC/SNAP Headers are encapsulated in the upper level
/// data, however, this data is encrypted and will show garbage information.
pub struct Frame {
    pub fc: FrameControl,
    pub duration: u16,
    pub addr1: Addr,
    pub addr2: Addr,
    pub addr3: Addr,
    pub addr4: Addr,
    pub seq_control: u16,
    pub llc: Option<LLCHeader>,
    pub snap: Option<SNAPHeader>,
    pub payload: Option<Payload>,
    pub crc: u16,
}

impl DatalinkFrame for Frame {
    fn get_payload(&self) -> &Option<Payload> {
        &self.payload
    }

    fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 MAC frame", |i| {
            let (i, fc, has_data) = {
                let (i, fc) = FrameControl::parse(i)?;
                let has_data = fc.typ == u2::new(2);
                (i, fc, has_data)
            };
            let (i, duration) = be_u16(i)?;
            let (i, (addr1, addr2, addr3, addr4)) =
                tuple((Addr::parse, Addr::parse, Addr::parse, Addr::parse))(i)?;
            let (i, seq_control) = be_u16(i)?;
            let (i, llc) = if has_data {
                let (i, header) = LLCHeader::parse(i)?;
                (i, Some(header))
            } else {
                (i, None)
            };

            let (i, mut snap) = if has_data {
                let (i, header) = SNAPHeader::parse(i)?;
                (i, Some(header))
            } else {
                (i, None)
            };

            let (i, payload) = if has_data && snap.is_some() {
                let (i, payload) = match snap.as_mut().unwrap().ether_type {
                    Some(EtherType::IPv4) => map(ipv4::Packet::parse, Payload::IPv4)(i)?,
                    Some(EtherType::IPv6) => map(ipv6::Packet::parse, Payload::IPv6)(i)?,
                    Some(EtherType::ARP) => map(arp::Packet::parse, Payload::ARP)(i)?,
                    _ => (i, Payload::Unknown),
                };
                (i, Some(payload))
            } else {
                (i, None)
            };

            let (i, crc) = be_u16(i)?;

            let res = Self {
                fc,
                duration,
                addr1,
                addr2,
                addr3,
                addr4,
                seq_control,
                llc,
                snap,
                payload,
                crc,
            };
            Ok((i, res))
        })(i)
    }
}
