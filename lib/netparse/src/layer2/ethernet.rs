use crate::{
    core::parse,
    layer2::{arp, datalink},
    layer3::ip::{ipv4, ipv6},
};

use custom_debug_derive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Frame {
    pub dst: datalink::Addr,
    pub src: datalink::Addr,
    pub ether_type: Option<datalink::EtherType>,
    pub payload: Option<datalink::Payload>,
}

impl Frame {
    pub fn parse(i: parse::Input) -> parse::ParseResult<Self> {
        context("Ethernet frame", |i| {
            let (i, (dst, src)) = tuple((datalink::Addr::parse, datalink::Addr::parse))(i)?;
            let (i, ether_type) = datalink::EtherType::parse(i)?;
            let (i, payload) = match ether_type {
                Some(datalink::EtherType::IPv4) => {
                    map(ipv4::Packet::parse, datalink::Payload::IPv4)(i)?
                }
                Some(datalink::EtherType::IPv6) => {
                    map(ipv6::Packet::parse, datalink::Payload::IPv6)(i)?
                }
                Some(datalink::EtherType::ARP) => {
                    map(arp::Packet::parse, datalink::Payload::ARP)(i)?
                }
                None => (i, datalink::Payload::Unknown),
            };

            let res = Self {
                dst,
                src,
                ether_type,
                payload: Some(payload),
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
        let dst_addr = datalink::Addr::new(&TEST_FRAME[..6]);
        let src_addr = datalink::Addr::new(&TEST_FRAME[6..12]);

        assert_eq!(frame.dst, dst_addr);
        assert_eq!(frame.src, src_addr);
        assert_eq!(frame.ether_type.unwrap(), datalink::EtherType::IPv4);
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
