extern crate bytes;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;

use bytes::{BufMut, BytesMut};
use tokio::io::Error;
use tokio_codec::{Decoder, Encoder};

#[derive(Debug, PartialEq)]
pub enum ClientEvents {
    IACWillNAWS,
    IACWontNAWS,
    // Terminal is now .0 wide and .1 high
    ResizeEvent(u16, u16),
    Byte(u8),
}

#[derive(Debug)]
pub enum ServerEvents {
    IACDoNAWS,
    IACDontNAWS,
    PassThrough(Vec<u8>),
}

#[derive(Default)]
pub struct TermionCodec(());

impl TermionCodec {
    pub fn new() -> Self {
        Default::default()
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

macro_rules! consume_event {
    ($bytes: expr, $take: expr, $evt: expr) => {{
        let _ = $bytes.split_to($take);
        Ok(Some($evt))
    }};
}

impl Decoder for TermionCodec {
    type Item = ClientEvents;
    type Error = Error;

    fn decode(&mut self, bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes[0] == IAC {
            match (bytes.get(1).cloned(), bytes.get(2).cloned()) {
                (Some(IAC), _) => consume_event!(bytes, 2, ClientEvents::Byte(IAC)),
                (Some(WILL), None) | (Some(WONT), None) | (Some(SB), None) => Ok(None),
                (Some(WILL), Some(NAWS)) => consume_event!(bytes, 3, ClientEvents::IACWillNAWS),
                (Some(WONT), Some(NAWS)) => consume_event!(bytes, 3, ClientEvents::IACWontNAWS),
                (Some(SB), Some(NAWS)) if bytes.len() < 9 => Ok(None),
                (Some(SB), Some(NAWS)) => {
                    let buf = bytes.split_to(9).freeze();
                    if let [IAC, SB, NAWS, w0, w1, h0, h1, IAC, SE] = *buf.as_ref() {
                        let h = u16::from_be_bytes([h0, h1]);
                        let w = u16::from_be_bytes([w0, w1]);
                        Ok(Some(ClientEvents::ResizeEvent(h, w)))
                    } else {
                        Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
                    }
                }
                _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            }
        } else {
            let b0 = bytes.split_to(1).freeze();
            Ok(Some(ClientEvents::Byte(b0[0])))
        }
    }
}

// https://tools.ietf.org/html/rfc854
const IAC: u8 = 255;
const SB: u8 = 250; // Subnegotiation Begin
const SE: u8 = 240; // Subnegotiation End
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

    macro_rules! assert_decodes_to {
        ($bytes: expr, $($event: expr),*$(,)?) => {{
            use futures::Stream;
            let mut iter = TermionCodec::new().framed(MockStream::new($bytes)).wait();
            $(assert_eq!($event, iter.next().expect("no next item").expect("task not ready"));)*
        }};
    }

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
        assert_decodes_to!(&[IAC, WILL, NAWS], ClientEvents::IACWillNAWS);
        assert_decodes_to!(&[IAC, WONT, NAWS], ClientEvents::IACWontNAWS);
    }

    #[test]
    fn decode_bytes_normal() {
        assert_decodes_to!(
            &[10, 20, 30],
            ClientEvents::Byte(10),
            ClientEvents::Byte(20),
            ClientEvents::Byte(30),
        );
    }

    #[test]
    fn decode_bytes_escape() {
        assert_decodes_to!(
            &[0x10, 0xFF, 0xFF],
            ClientEvents::Byte(0x10),
            ClientEvents::Byte(0xFF),
        );
    }

    #[test]
    fn decode_resize_event() {
        assert_decodes_to!(
            &[255, 250, 31, 0, 80, 0, 64, 255, 240],
            ClientEvents::ResizeEvent(64, 80)
        )
    }

    #[test]
    fn decode_many() {
        assert_decodes_to!(
            &[1, 1, 2, 3, IAC, WILL, NAWS, 99, 255, 255, IAC, SB, NAWS, 0, 80, 0, 40, IAC, SE, 20],
            ClientEvents::Byte(1),
            ClientEvents::Byte(1),
            ClientEvents::Byte(2),
            ClientEvents::Byte(3),
            ClientEvents::IACWillNAWS,
            ClientEvents::Byte(99),
            ClientEvents::Byte(255),
            ClientEvents::ResizeEvent(40, 80)
        )
    }
}
