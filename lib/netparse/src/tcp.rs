use crate::{
    blob::Blob,
    parse::{self, BitParsable},
    ux::*,
};

use custom_debug_derive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    combinator::map,
    error::context,
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Options {
    Data(DataOptions),
    NoData(NoData),
    Empty,
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct DataOptions {
    #[debug(format = "{:02X}")]
    kind: u8,
    #[debug(format = "{}")]
    len: u8,
    data: Blob,
}

impl DataOptions {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("TCP Options", |i| {
            let (i, kind) = be_u8(i)?;
            let (i, len) = be_u8(i)?;
            let (i, data) = take(len)(i)?;
            let res = Self {
                kind,
                len,
                data: Blob::new(data),
            };
            Ok((i, res))
        })(i)
    }
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct NoData {
    #[debug(format = "{:02X}")]
    kind: u8,
}

impl NoData {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("TCP Options", |i| {
            let (i, kind) = be_u8(i)?;
            let res = Self { kind };
            Ok((i, res))
        })(i)
    }
}

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Packet {
    #[debug(format = "{}")]
    src_port: u16,
    #[debug(format = "{}")]
    dst_port: u16,
    #[debug(format = "{:04x}")]
    seq_num: u32,
    #[debug(format = "{:04x}")]
    ack_num: u32,
    #[debug(format = "{}")]
    offset: u4,
    #[debug(format = "{}")]
    reserved: u3,
    #[debug(format = "{}")]
    ns: u1,
    #[debug(format = "{}")]
    cwr: u1,
    #[debug(format = "{}")]
    ece: u1,
    #[debug(format = "{}")]
    urg: u1,
    #[debug(format = "{}")]
    ack: u1,
    #[debug(format = "{}")]
    psh: u1,
    #[debug(format = "{}")]
    rst: u1,
    #[debug(format = "{}")]
    syn: u1,
    #[debug(format = "{}")]
    fin: u1,
    #[debug(format = "{}")]
    window_size: u16,
    #[debug(format = "{:04x}")]
    checksum: u16,
    #[debug(format = "{:04x}")]
    urgent_ptr: u16,
    options: Options,
    payload: Blob,
}

impl Packet {
    fn get_options(i: parse::Input, offset: u4) -> parse::Result<Options> {
        if offset > u4::new(5) {
            if i[0] == 0x00 || i[0] == 0x01 {
                map(NoData::parse, Options::NoData)(i)
            } else {
                map(DataOptions::parse, Options::Data)(i)
            }
        } else {
            Ok((i, Options::Empty))
        }
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("TCP Frame", |i| {
            let (i, (src_port, dst_port, seq_num, ack_num)) =
                tuple((be_u16, be_u16, be_u32, be_u32))(i)?;
            let (i, (offset, reserved, ns, cwr, ece, urg, ack, psh, rst, syn, fin)) =
                bits(tuple((
                    u4::parse,
                    u3::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                    u1::parse,
                )))(i)?;

            let (i, (window_size, checksum, urgent_ptr)) = tuple((be_u16, be_u16, be_u16))(i)?;
            let (i, options) = Packet::get_options(i, offset)?;
            let payload = Blob::new(i);

            let res = Self {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                offset,
                reserved,
                ns,
                cwr,
                ece,
                urg,
                ack,
                psh,
                rst,
                syn,
                fin,
                window_size,
                checksum,
                urgent_ptr,
                options,
                payload,
            };

            Ok((i, res))
        })(i)
    }
}
