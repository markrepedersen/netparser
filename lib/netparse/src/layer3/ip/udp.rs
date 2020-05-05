use crate::core::{blob::Blob, parse};

use custom_debug_derive::*;
use nom::{error::context, number::complete::be_u16, sequence::tuple};
use serde::{Deserialize, Serialize};

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct Datagram {
    #[debug(format = "{}")]
    pub src_port: u16,
    #[debug(format = "{}")]
    pub dst_port: u16,
    #[debug(format = "{}")]
    pub len: u16,
    #[debug(format = "{:04x}")]
    pub checksum: u16,
    pub payload: Blob,
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
