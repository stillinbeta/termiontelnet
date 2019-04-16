extern crate tokio;
extern crate tokio_codec;

extern crate bytes;

use bytes::{BufMut, BytesMut};
use tokio::io::Error;
use tokio_codec::{Decoder, Encoder};

pub enum ClientEvents {
    IACWillNAWS,
    IACWontNAWS,
    ResizeEvent(u16, u16),
    PassThrough(Vec<u8>),
}

pub enum ServerEvents {
    IACDoNAWS,
    IACDontNAWS,
    PassThrough(Vec<u8>),
}

pub struct TermionCodec(());

impl TermionCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Encoder for TermionCodec {
    type Item = ServerEvents;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            ServerEvents::IACDontNAWS => {
                dst.reserve(3);
                dst.put(&[IAC, DONT, NAWS] as &[u8]);
            }
            ServerEvents::IACDoNAWS => {
                dst.reserve(3);
                dst.put(&[IAC, DO, NAWS] as &[u8]);
            }
            ServerEvents::PassThrough(v) => {
                dst.reserve(v.len());
                for b in v {
                    if b == IAC {
                        dst.reserve(1);
                        dst.put(&[IAC, IAC] as &[u8]);
                    } else {
                        dst.put(b)
                    }
                }
            }
        };
        Ok(())
    }
}

impl Decoder for TermionCodec {
    type Item = ClientEvents;
    type Error = Error;

    fn decode(&mut self, _bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        unimplemented!()
    }
}

// https://tools.ietf.org/html/rfc854
const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
// https://tools.ietf.org/html/rfc1073
const NAWS: u8 = 31;

#[cfg(test)]
mod test {
    use super::*;
    use std::borrow::Borrow;

    macro_rules! assert_encode_type {
        ($event: expr, $expected: expr) => {
            let mut buf = BytesMut::new();
            TermionCodec::new()
                .encode($event, &mut buf)
                .expect("failed to encode");
            let actual: &[u8] = buf.borrow();
            assert_eq!($expected, actual);
        };
    }

    #[test]
    fn encode_iac() {
        assert_encode_type!(ServerEvents::IACDontNAWS, &[IAC, DONT, NAWS]);
        assert_encode_type!(ServerEvents::IACDoNAWS, &[IAC, DO, NAWS]);
    }

    #[test]
    fn encode_payload_normal() {
        assert_encode_type!(
            ServerEvents::PassThrough(vec![0x10, 0x20, 0x30]),
            &[0x10, 0x20, 0x30]
        );
    }

    #[test]
    fn encode_escape() {
        assert_encode_type!(
            ServerEvents::PassThrough(vec![0x10, 0xFF, 0x20]),
            &[0x10, 0xFF, 0xFF, 0x20]
        );
    }
}
