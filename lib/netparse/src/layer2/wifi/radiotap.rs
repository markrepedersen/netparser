use crate::core::parse;

use custom_debug_derive::*;
use nom::{
    bytes::complete::take,
    error::context,
    number::complete::{le_u16, le_u32, le_u8},
};
use serde::{Deserialize, Serialize};

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct RadioTapHeader {
    #[debug(format = "0x{:02X}")]
    pub it_version: u8,
    #[debug(format = "{}")]
    pub it_pad: u8,
    #[debug(format = "{}")]
    pub it_len: u16,
    #[debug(format = "0x{:04X}")]
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
