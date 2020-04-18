use crate::{blob::Blob, parse};

use custom_debug_derive::*;
use nom::{error::context, number::complete::be_u16, sequence::tuple};

#[derive(CustomDebug)]
pub struct Datagram {
    #[debug(format = "{}")]
    src_port: u16,
    #[debug(format = "{}")]
    dst_port: u16,
    #[debug(format = "{}")]
    len: u16,
    #[debug(format = "{:04x}")]
    checksum: u16,
    payload: Blob,
}

impl Datagram {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("UDP Frame", |i| {
            let (i, (src_port, dst_port, len, checksum)) =
                tuple((be_u16, be_u16, be_u16, be_u16))(i)?;
            let payload = Blob::new(i);

            let res = Self {
                src_port,
                dst_port,
                len,
                checksum,
                payload,
            };

            Ok((i, res))
        })(i)
    }
}
