use crate::parse;

use custom_debug_derive::*;
use nom::{
    bytes::complete::take,
    error::context,
    number::complete::{be_u16, be_u8},
};
use std::fmt;

#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct Addr(pub [u8; 16]);

impl fmt::Display for Addr {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let ipv6 = &self.0;
        let ipv6_len = ipv6.len();
        let mut res = String::new();

        for (i, byte) in ipv6.iter().enumerate() {
            if i % 2 == 0 || i == ipv6_len - 1 {
                res.push_str(&format!("{:02X}", byte));
            } else {
                res.push_str(&format!("{:02X}:", byte));
            }
        }
        write!(w, "{}", res)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, slice) = context("IPv6 address", take(16_usize))(i)?;
        let mut res = Self::default();
        res.0.copy_from_slice(slice);
        Ok((i, res))
    }
}

#[derive(CustomDebug)]
pub struct Packet {
    #[debug(format = "{}")]
    payload_len: u16,
    #[debug(format = "{}")]
    next_header: u8,
    #[debug(format = "{}")]
    ttl: u8,
    src: Addr,
    dst: Addr,
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("IPv6 frame", |i| {
            let (i, _) = take(4usize)(i)?;
            let (i, payload_len) = be_u16(i)?;
            let (i, next_header) = be_u8(i)?;
            let (i, ttl) = be_u8(i)?;
            let (i, src) = Addr::parse(i)?;
            let (i, dst) = Addr::parse(i)?;
            let res = Self {
                payload_len,
                next_header,
                ttl,
                src,
                dst,
            };

            Ok((i, res))
        })(i)
    }
}
