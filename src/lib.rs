extern crate futures;
extern crate tokio;
extern crate tokio_codec;

extern crate bytes;

use bytes::{BufMut, BytesMut};
use tokio::io::Error;
use tokio_codec::{Decoder, Encoder};

#[derive(Debug, PartialEq)]
pub enum ClientEvents {
    IACWillNAWS,
    IACWontNAWS,
    ResizeEvent(u16, u16),
    PassThrough(Vec<u8>),
}

#[derive(Debug)]
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
        match dbg!(item) {
            ServerEvents::IACDontNAWS => {
                dst.extend_from_slice(&[IAC, DONT, NAWS]);
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
    extern crate tokio_mockstream;
    use tokio_mockstream::MockStream;

    macro_rules! assert_encodes_to {
        ($event: expr, $expected: expr) => {{
            use futures::{Future, Sink};

            let stream = TermionCodec::new().framed(MockStream::empty());
            let stream = stream.send($event).wait().unwrap();
            assert_eq!($expected, stream.into_inner().written());
        }};
    }

    // macro_rules! assert_decodes_to {
    //     $(event: expr, bytes: $expr) => {

    //     }
    // }

    #[test]
    fn encode_iac() {
        assert_encodes_to!(ServerEvents::IACDontNAWS, &[IAC, DONT, NAWS]);
        assert_encodes_to!(ServerEvents::IACDoNAWS, &[IAC, DO, NAWS]);
    }

    #[test]
    fn encode_payload_normal() {
        assert_encodes_to!(
            ServerEvents::PassThrough(vec![0x10, 0x20, 0x30]),
            &[0x10, 0x20, 0x30]
        );
    }

    #[test]
    fn encode_escape() {
        assert_encodes_to!(
            ServerEvents::PassThrough(vec![0x10, 0xFF, 0x20]),
            &[0x10, 0xFF, 0xFF, 0x20]
        );
    }

    #[test]
    fn decode_iac() {
        use futures::Stream;

        let mut iter = TermionCodec::new()
            .framed(MockStream::new(&[IAC, WILL, NAWS]))
            .wait();
        assert_eq!(ClientEvents::IACWillNAWS, iter.next().unwrap().unwrap())
    }
}
