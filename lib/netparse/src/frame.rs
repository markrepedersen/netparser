use crate::{arp, datalink, datalink::*, ipv4, ipv6, parse};

use custom_debug_derive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, CustomDebug)]
pub struct Frame {
    pub dst: Addr,
    pub src: Addr,
    pub ether_type: Option<EtherType>,
    pub payload: Option<datalink::Payload>,
}

impl DatalinkFrame for Frame {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        context("Ethernet frame", |i| {
            let (i, (dst, src)) = tuple((Addr::parse, Addr::parse))(i)?;
            let (i, ether_type) = EtherType::parse(i)?;
            let (i, payload) = match ether_type {
                Some(EtherType::IPv4) => map(ipv4::Packet::parse, Payload::IPv4)(i)?,
                Some(EtherType::IPv6) => map(ipv6::Packet::parse, Payload::IPv6)(i)?,
                Some(EtherType::ARP) => map(arp::Packet::parse, Payload::ARP)(i)?,
                None => (i, Payload::Unknown),
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

    fn get_payload(&self) -> &Option<Payload> {
        &self.payload
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
        let dst_addr = Addr::new(&TEST_FRAME[..6]);
        let src_addr = Addr::new(&TEST_FRAME[6..12]);

        assert_eq!(frame.dst, dst_addr);
        assert_eq!(frame.src, src_addr);
        assert_eq!(frame.ether_type.unwrap(), EtherType::IPv4);
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
