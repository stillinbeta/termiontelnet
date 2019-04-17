extern crate bytes;
extern crate futures;
extern crate termion;
extern crate tokio;
extern crate tokio_codec;

use bytes::{BufMut, BytesMut};
use std::io::{Error, ErrorKind, Read};
use std::iter::FromIterator;
use tokio_codec::{Decoder, Encoder};

/// Events received from the telnet client
#[derive(Debug, PartialEq)]
pub enum ClientEvents {
    /// The client has agreed to Negotiate About Window Size
    IACWillNAWS,
    /// The client has refused to Negiotiate About Window Size
    IACWontNAWS,
    /// Terminal is now .0 wide and .1 high
    ResizeEvent(u16, u16),
    /// A keypress or mouse event
    TermionEvent(termion::event::Event),
}

/// Events sent to the telnet client
#[derive(Debug)]
pub enum ServerEvents {
    /// Indicate the server's desire to Negotiate About Window Size
    IACDoNAWS,
    /// Indicate the server's refusal to Negotiate About Window Size
    IACDontNAWS,
    /// Pass arbitrary bytes to the client
    PassThrough(Vec<u8>),
}

/// This codec parses an incoming stream of data as a series of terminal events.
#[derive(Default)]
pub struct TelnetCodec(());

impl TelnetCodec {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Encoder for TelnetCodec {
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

impl Decoder for TelnetCodec {
    type Item = ClientEvents;
    type Error = Error;

    fn decode(&mut self, bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if bytes.is_empty() {
            return Ok(None);
        }
        // TODO: If an IAC sequence interrupts a terminal escape, this will fail
        if bytes[0] == IAC {
            match (bytes.get(1).cloned(), bytes.get(2).cloned()) {
                // (Some(IAC), _) => consume_event!(bytes, 2, ClientEvents::Byte(IAC)),
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
            // TODO: can we get rid of this?
            let bytes2 = bytes.clone();
            let mut iter = bytes2.bytes().skip(1);
            termion::event::parse_event(bytes[0], &mut iter)
                .and_then(|evt| {
                    bytes.clear();
                    bytes.extend(BytesMut::from_iter(iter.filter_map(|v| v.ok())));
                    Ok(Some(ClientEvents::TermionEvent(evt)))
                })
                .or_else(|err| {
                    if err.kind() == ErrorKind::WouldBlock {
                        Ok(None)
                    } else {
                        Err(err)
                    }
                })
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

    use termion::event::{Event, Key};

    macro_rules! assert_encodes_to {
        ($event: expr, $expected: expr) => {{
            use futures::{Future, Sink};

            let stream = TelnetCodec::new().framed(MockStream::empty());
            let stream = stream.send($event).wait().unwrap();
            assert_eq!($expected, stream.into_inner().written());
        }};
    }

    macro_rules! assert_decodes_to {
        ($bytes: expr, $($event: expr),*$(,)?) => {{
            use futures::Stream;
            let mut iter = TelnetCodec::new().framed(MockStream::new($bytes)).wait();
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
            &[b'\x1B', b'O', b'S'],
            ClientEvents::TermionEvent(Event::Key(Key::F(4)))
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
            &[
                b'\x7f', IAC, WILL, NAWS, 0, IAC, SB, NAWS, 0, 80, 0, 40, IAC, SE, b'\x1B', b'[',
                b'A'
            ],
            ClientEvents::TermionEvent(Event::Key(Key::Backspace)),
            ClientEvents::IACWillNAWS,
            ClientEvents::TermionEvent(Event::Key(Key::Null)),
            ClientEvents::ResizeEvent(40, 80),
            ClientEvents::TermionEvent(Event::Key(Key::Up)),
        )
    }
}
