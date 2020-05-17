use crate::{
    core::{
        blob::Blob,
        parse::{self, BitParsable},
        ux::*,
    },
    layer2::{datalink::*, wifi::data::*, wifi::management::*},
};

use custom_debug_derive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    error::context,
    number::complete::{le_u16, le_u32},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};

pub static SEQ_CONTROL_SIZE: usize = 4;

#[derive(Debug, Serialize, Deserialize)]
pub enum Dot11Addr {
    /// The destination is the station that will process the network-layer packet contained in the frame.
    DestinationAddress(Addr),
    /// The receiver is the station that will attempt to decode the radio waves into an 802.11 frame
    ReceiverAddress(Addr),
    /// The sender is the frame that generated the network-layer protocol packet in the frame.
    SourceAddress(Addr),
    /// Used to send acknowledgments.
    /// Transmitters are not necessarily senders.
    /// The transmitter puts the frame on to the radio link.
    TransmitterAddress(Addr),
    /// Only when set to a broadcast or multicast address.
    /// Stations respond only to broadcasts and multicasts originating in the same basic service set (BSS); they ignore broadcasts and multicasts from different BSSIDs
    BSSID(Addr),
}

#[derive(CustomDebug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Type {
    Management = 0x0,
    Control,
    Data,
    Extension,
}

impl From<u2> for Type {
    fn from(i: u2) -> Self {
        match i {
            i if i == u2::new(0x0) => Type::Management,
            i if i == u2::new(0x1) => Type::Control,
            i if i == u2::new(0x2) => Type::Data,
            _ => Type::Extension,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(CustomDebug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Subtype {
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
    RequestToSend,
    ClearToSend,
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
    Unknown,
}

impl Subtype {
    fn from_type(typ: Type, i: u4) -> Self {
        match i {
            i if typ == Type::Management && i == u4::new(0x0) => Subtype::AssociationRequest,
            i if typ == Type::Management && i == u4::new(0x1) => Subtype::AssociationResponse,
            i if typ == Type::Management && i == u4::new(0x2) => Subtype::ReassociationRequest,
            i if typ == Type::Management && i == u4::new(0x3) => Subtype::ReassociationResponse,
            i if typ == Type::Management && i == u4::new(0x4) => Subtype::ProbeRequest,
            i if typ == Type::Management && i == u4::new(0x5) => Subtype::ProbeResponse,
            i if typ == Type::Management && i == u4::new(0x6) => Subtype::TimingAdvertisement,
            i if typ == Type::Management && i == u4::new(0x7) => Subtype::Reserved1,
            i if typ == Type::Management && i == u4::new(0x8) => Subtype::Beacon,
            i if typ == Type::Management && i == u4::new(0x9) => Subtype::ATIM,
            i if typ == Type::Management && i == u4::new(0xA) => Subtype::Disassociation,
            i if typ == Type::Management && i == u4::new(0xB) => Subtype::Authentication,
            i if typ == Type::Management && i == u4::new(0xC) => Subtype::Deauthentication,
            i if typ == Type::Management && i == u4::new(0xD) => Subtype::Action,
            i if typ == Type::Management && i == u4::new(0xE) => Subtype::NACK,
            i if typ == Type::Management && i == u4::new(0xF) => Subtype::Reserved2,
            i if typ == Type::Control && (i == u4::new(0x0) || i == u4::new(0x1)) => {
                Subtype::Reserved3
            }
            i if typ == Type::Control && i == u4::new(0x2) => Subtype::Trigger,
            i if typ == Type::Control && i == u4::new(0x4) => Subtype::BeamformingReportPoll,
            i if typ == Type::Control && i == u4::new(0x5) => Subtype::VHT_OR_HE_NDP_Announcement,
            i if typ == Type::Control && i == u4::new(0x6) => Subtype::ControlFrameExtension,
            i if typ == Type::Control && i == u4::new(0x7) => Subtype::ControlWrapper,
            i if typ == Type::Control && i == u4::new(0x8) => Subtype::BAR,
            i if typ == Type::Control && i == u4::new(0x9) => Subtype::BA,
            i if typ == Type::Control && i == u4::new(0xA) => Subtype::PSPoll,
            i if typ == Type::Control && i == u4::new(0xB) => Subtype::RequestToSend,
            i if typ == Type::Control && i == u4::new(0xC) => Subtype::ClearToSend,
            i if typ == Type::Control && i == u4::new(0xD) => Subtype::ACK,
            i if typ == Type::Control && i == u4::new(0xE) => Subtype::CFEnd,
            i if typ == Type::Control && i == u4::new(0xF) => Subtype::CFEnd_And_CFAck,
            i if typ == Type::Data && i == u4::new(0x0) => Subtype::Data,
            i if typ == Type::Data && i == u4::new(0x1) => Subtype::Data_And_CFAck,
            i if typ == Type::Data && i == u4::new(0x2) => Subtype::Data_And_CFPoll,
            i if typ == Type::Data && i == u4::new(0x3) => Subtype::Data_And_CFAck_And_CFPoll,
            i if typ == Type::Data && i == u4::new(0x4) => Subtype::Null,
            i if typ == Type::Data && i == u4::new(0x5) => Subtype::CFAck_NoData,
            i if typ == Type::Data && i == u4::new(0x6) => Subtype::CFPoll_NoData,
            i if typ == Type::Data && i == u4::new(0x7) => Subtype::CFAck_And_CFPoll_NoData,
            i if typ == Type::Data && i == u4::new(0x8) => Subtype::QoSData,
            i if typ == Type::Data && i == u4::new(0x9) => Subtype::QoSData_And_CFAck,
            i if typ == Type::Data && i == u4::new(0xA) => Subtype::QoSData_And_CFPoll,
            i if typ == Type::Data && i == u4::new(0xB) => Subtype::QoSData_And_CFAck_And_CFPoll,
            i if typ == Type::Data && i == u4::new(0xC) => Subtype::QoSNull,
            i if typ == Type::Data && i == u4::new(0xD) => Subtype::Reserved4,
            i if typ == Type::Data && i == u4::new(0xE) => Subtype::QoS_CFPoll,
            i if typ == Type::Data && i == u4::new(0xF) => Subtype::QoS_CFAck_And_CFPoll,
            i if typ == Type::Extension && i == u4::new(0x0) => Subtype::DMGBeacon,
            i if typ == Type::Extension && i != u4::new(0x0) => Subtype::Reserved5,
            _ => Subtype::Unknown,
        }
    }
}

#[derive(CustomDebug, Serialize, Deserialize, Clone)]
pub struct ControlFlags {
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
    pub protected: u1,

    #[debug(format = "{}")]
    pub order: u1,
}

impl ControlFlags {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("802.11 Frame Control Flags", |i| {
	    let (i, (order, protected, more_data, power_mgmt, retry, more_fragments, from_ds, to_ds)) =
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
                to_ds,
                from_ds,
                more_fragments,
                retry,
                power_mgmt,
                more_data,
                protected,
                order,
            };

            return Ok((i, res));
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize, Clone)]
pub struct FrameControl {
    #[debug(format = "{}")]
    pub version: u2,
    pub typ: Type,
    pub subtype: Subtype,
    pub flags: ControlFlags,
}

impl FrameControl {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("802.11 Frame Control", |i| {
            let (i, (subtype, typ, version)) = bits(tuple((u4::parse, u2::parse, u2::parse)))(i)?;
	    let (i, flags) = ControlFlags::parse(i)?;
            let typ = Type::from(typ);
            let subtype = Subtype::from_type(typ.clone(), subtype);
            let res = Self {
                version,
                typ,
                subtype,
		flags
            };

            return Ok((i, res));
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SeqControl {
    #[debug(format = "{}")]
    pub frag_num: u4,
    #[debug(format = "{}")]
    pub seq_num: u12,
}

impl SeqControl {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("802.11 Sequence Control", |i| {
            let (i, (frag_num, seq_num)) = bits(tuple((u4::parse, u12::parse)))(i)?;
            let res = Self { frag_num, seq_num };
            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub enum FrameBody {
    Data(DataFrameBody),
    Beacon(BeaconFrameBody),
    ProbeRequest(ProbeRequestFrameBody),
    ProbeResponse(ProbeResponseFrameBody),
    Deauthentication(DeauthenticationFrameBody),
    Disassociation(ReasonCode),
    Authentication(AuthenticationFrameBody),
    AssociationRequest(AssociationRequestFrameBody),
    ReassociationRequest(ReassociationRequestFrameBody),
    AssociationResponse(AssociationResponseFrameBody),
    ReassociationResponse(AssociationResponseFrameBody),
    Encrypted(Blob),
    Empty,
    Malformed,
}

impl FrameBody {
    fn parse<'a>(fc: &FrameControl, i: parse::Input<'a>) -> parse::ParseResult<'a, Self> {
        if fc.flags.protected == u1::new(1) {
            if let Some(len) = i.len().checked_sub(SEQ_CONTROL_SIZE) {
                let (i, _) = take(len)(i)?;
                let blob = Blob::new(i);
                return Ok((i, FrameBody::Encrypted(blob)));
            } else {
                return Ok((i, FrameBody::Empty));
            }
        }
        Ok(match fc.typ {
            Type::Data => match fc.subtype {
                Subtype::Data
                | Subtype::Data_And_CFAck
                | Subtype::Data_And_CFPoll
                | Subtype::Data_And_CFAck_And_CFPoll
                | Subtype::QoSData
                | Subtype::QoSData_And_CFAck
                | Subtype::QoSData_And_CFPoll
                | Subtype::QoSData_And_CFAck_And_CFPoll => {
                    let (i, body) = DataFrameBody::parse(i)?;
                    (i, FrameBody::Data(body))
                }
                _ => (i, FrameBody::Empty),
            },

            Type::Management => match fc.subtype {
                Subtype::Beacon => {
                    let (i, body) = BeaconFrameBody::parse(i)?;
                    (i, FrameBody::Beacon(body))
                }

                Subtype::ProbeRequest => {
                    let (i, body) = ProbeRequestFrameBody::parse(i)?;
                    (i, FrameBody::ProbeRequest(body))
                }

                Subtype::ProbeResponse => {
                    let (i, body) = ProbeResponseFrameBody::parse(i)?;
                    (i, FrameBody::ProbeResponse(body))
                }

                Subtype::Deauthentication | Subtype::Disassociation => {
                    let (i, body) = DeauthenticationFrameBody::parse(i)?;
                    (i, FrameBody::Deauthentication(body))
                }

                Subtype::Authentication => {
                    let (i, body) = AuthenticationFrameBody::parse(i)?;
                    (i, FrameBody::Authentication(body))
                }

                Subtype::AssociationRequest => {
                    let (i, body) = AssociationRequestFrameBody::parse(i)?;
                    (i, FrameBody::AssociationRequest(body))
                }

                Subtype::ReassociationRequest => {
                    let (i, body) = ReassociationRequestFrameBody::parse(i)?;
                    (i, FrameBody::ReassociationRequest(body))
                }

                Subtype::AssociationResponse | Subtype::ReassociationResponse => {
                    let (i, body) = AssociationResponseFrameBody::parse(i)?;
                    (i, FrameBody::AssociationResponse(body))
                }

                _ => (i, FrameBody::Empty),
            },

            _ => (i, FrameBody::Empty),
        })
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
/// The MAC Frame header.
/// - LLC/SNAP Headers are encapsulated in the upper level.
/// - Note that LLC/SNAP header and data are WEP or WPA/WPA2 encrypted, so these bytes will not be representative of the actual data.
pub struct Frame {
    pub fc: FrameControl,
    #[debug(format = "{}")]
    pub duration: u16,
    pub addr1: Dot11Addr,
    pub addr2: Option<Dot11Addr>,
    pub addr3: Option<Dot11Addr>,
    pub seq_control: Option<SeqControl>,
    pub addr4: Option<Dot11Addr>,
    pub frame_body: FrameBody,
    #[debug(format = "0x{:08X}")]
    pub fcs: u32,
}

impl Frame {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn parse_addr(i: parse::Input, fc: FrameControl) -> parse::ParseResult<(Dot11Addr, Option<Dot11Addr>, Option<Dot11Addr>, Option<SeqControl>, Option<Dot11Addr>)> {
	use Dot11Addr::*;
        let res = match fc.typ {
            Type::Data => {
		let (i, (addr1, addr2, addr3, seq_control)) = tuple((Addr::parse, Addr::parse, Addr::parse, SeqControl::parse))(i)?;
		match fc.flags {
                    ControlFlags { to_ds: x, from_ds: y, .. } if x == u1::new(0) && y == u1::new(0) => {
			(i, (DestinationAddress(addr1), Some(SourceAddress(addr2)), Some(BSSID(addr3)), Some(seq_control), None))
                    }
                    ControlFlags { to_ds: x, from_ds: y, .. } if x == u1::new(1) && y == u1::new(0) => {
			(i, (BSSID(addr1), Some(SourceAddress(addr2)), Some(DestinationAddress(addr3)), Some(seq_control), None))
                    }
                    ControlFlags { to_ds: x, from_ds: y, .. } if x == u1::new(0) && y == u1::new(1) => {
			(i, (DestinationAddress(addr1), Some(BSSID(addr2)), Some(SourceAddress(addr3)), Some(seq_control), None))
                    }
                    _ => {
			let (i, addr4) = Addr::parse(i)?;
			(i, (ReceiverAddress(addr1), Some(TransmitterAddress(addr2)), Some(DestinationAddress(addr3)), Some(seq_control), Some(SourceAddress(addr4))))
                    }
		}
	    },
            Type::Control => match fc.subtype {
                Subtype::RequestToSend => {
                    let (i, (addr1, addr2)) = tuple((Addr::parse, Addr::parse))(i)?;
                    (i, (ReceiverAddress(addr1), Some(TransmitterAddress(addr2)), None, None, None))
                }
		Subtype::PSPoll => {
                    let (i, (addr1, addr2)) = tuple((Addr::parse, Addr::parse))(i)?;
                    (i, (BSSID(addr1), Some(TransmitterAddress(addr2)), None, None, None))
                }
                _ => {
                    let (i, addr1) = Addr::parse(i)?;
                    (i, (ReceiverAddress(addr1), None, None, None, None))
                }
            },
            Type::Management => {
		let (i, (addr1, addr2, addr3, seq_control)) = tuple((Addr::parse, Addr::parse, Addr::parse, SeqControl::parse))(i)?;
                (i, (DestinationAddress(addr1), Some(SourceAddress(addr2)), Some(BSSID(addr3)), Some(seq_control), None))
	    },
            _ => {
                let (i, addr1) = Addr::parse(i)?;
                (i, (ReceiverAddress(addr1), None, None, None, None))
            }
        };

	Ok(res)
    }
}

impl Frame {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("802.11 MAC frame", |i| {
            let (i, fc) = FrameControl::parse(i)?;
            let (i, duration) = le_u16(i)?;
            let (i, (addr1, addr2, addr3, seq_control, addr4)) = Frame::parse_addr(i, fc.clone())?;
            let (i, frame_body) = FrameBody::parse(&fc, i)?;
            let (i, fcs) = le_u32(i)?;
            let res = Self {
                fc,
                duration,
                addr1,
                addr2,
                addr3,
                addr4,
                seq_control,
                frame_body,
                fcs,
            };
            Ok((i, res))
        })(i)
    }
}
