use crate::blob::Blob;
use crate::parse;

use custom_debug_derive::*;
use nom::{
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
};

#[derive(Debug)]
pub enum Type {
    EchoReply,
    DestinationUnreachable(DestinationUnreachable),
    EchoRequest,
    TimeExceeded(TimeExceeded),
    Other(u8, u8),
}

#[derive(Debug)]
pub enum DestinationUnreachable {
    HostUnreachable,
    Other(u8),
}

#[derive(Debug)]
pub enum TimeExceeded {
    TTLExpired,
    Other(u8),
}

#[derive(CustomDebug)]
pub struct Echo {
    #[debug(format = "{:04x}")]
    pub identifier: u16,
    #[debug(format = "{:04x}")]
    pub sequence_number: u16,
}

impl Echo {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        context("Echo", |i| {
            map(tuple((be_u16, be_u16)), |(identifier, sequence_number)| {
                Echo {
                    identifier,
                    sequence_number,
                }
            })(i)
        })(i)
    }
}

#[derive(Debug)]
pub enum Header {
    EchoRequest(Echo),
    EchoReply(Echo),
    Other(u32),
}

impl From<(u8, u8)> for Type {
    fn from(x: (u8, u8)) -> Self {
        let (typ, code) = x;

        match typ {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable(code.into()),
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded(code.into()),
            _ => Self::Other(typ, code),
        }
    }
}

impl From<u8> for DestinationUnreachable {
    fn from(x: u8) -> Self {
        match x {
            1 => Self::HostUnreachable,
            x => Self::Other(x),
        }
    }
}

impl From<u8> for TimeExceeded {
    fn from(x: u8) -> Self {
        match x {
            0 => Self::TTLExpired,
            x => Self::Other(x),
        }
    }
}

#[derive(CustomDebug)]
pub struct Packet {
    pub typ: Type,
    #[debug(format = "{:02X}")]
    pub checksum: u16,
    #[debug(format = "{:?}")]
    pub header: Header,
    pub payload: Blob,
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("ICMP frame", |i| {
            let (i, typ) = {
                let (i, (typ, code)) = tuple((be_u8, be_u8))(i)?;
                (i, Type::from((typ, code)))
            };
            let (i, checksum) = be_u16(i)?;
            let (i, header) = match typ {
                Type::EchoRequest => map(Echo::parse, Header::EchoRequest)(i)?,
                Type::EchoReply => map(Echo::parse, Header::EchoReply)(i)?,
                _ => map(be_u32, Header::Other)(i)?,
            };
            let payload = Blob::new(i);

            let res = Self {
                typ,
                checksum,
                header,
                payload,
            };
            Ok((i, res))
        })(i)
    }
}
