#![allow(clippy::useless_attribute)] // https://github.com/rust-num/num-derive/issues/20
extern crate bytes;
extern crate futures;
extern crate termion;
extern crate tokio;
extern crate tokio_codec;
#[macro_use]
extern crate num_derive;
extern crate num_traits;

use bytes::{BufMut, BytesMut};
use num_traits::FromPrimitive;
use std::io::{Error, ErrorKind, Read};
use std::iter::FromIterator;
use tokio_codec::{Decoder, Encoder};

#[cfg(test)]
mod tests;

// https://tools.ietf.org/html/rfc854
const IAC: u8 = 255;
const SB: u8 = 250; // Subnegotiation Begin
const SE: u8 = 240; // Subnegotiation End
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;

/// Events received from the telnet client
#[derive(Debug, PartialEq, Clone)]
pub enum ClientEvents {
    /// The client has agreed to the specified option
    Will(TelnetOption),
    /// The client has refused the specified option
    Wont(TelnetOption),
    /// The client demands a stop to the specific option
    Dont(TelnetOption),
    /// The client requests the specific option
    Do(TelnetOption),
    /// Terminal is now .0 wide and .1 high
    ResizeEvent(u16, u16),

    /// The client sent a suboption, but it's not one we know how to decode.
    RawSuboption(TelnetOption, Vec<u8>),
    /// A keypress or mouse event
    TermionEvent(termion::event::Event),
}

/// Various telnet options that can be negotiated
#[derive(Debug, PartialEq, Clone, FromPrimitive)]
pub enum TelnetOption {
    /// https://tools.ietf.org/html/rfc857
    Echo = 1,
    /// https://tools.ietf.org/html/rfc858
    SupressGoAhead = 3,
    /// https://tools.ietf.org/html/rfc859
    Status = 5,
    /// https://tools.ietf.org/html/rfc860
    TimingMark = 24,
    /// https://tools.ietf.org/html/rfc1073
    WindowSize = 31,
    /// https://tools.ietf.org/html/rfc1079
    TerminalSpeed = 32,
    /// https://tools.ietf.org/html/rfc1080
    RemoteFlowControl = 33,
    /// https://tools.ietf.org/html/rfc1184
    LineMode = 34,
    /// https://tools.ietf.org/html/rfc1408
    EnvironmentVariables = 36,
    /// https://tools.ietf.org/html/draft-rfced-exp-atmar-00
    SupressLocalEcho = 41,
}

/// Events sent to the telnet client
#[derive(Debug)]
pub enum ServerEvents {
    /// Indicate the server's desire to use the given telnet option
    Do(TelnetOption),
    /// Indicate the server's refusal to use the given telnet option
    Dont(TelnetOption),
    /// Indicate the server's desire to use the given telnet option
    Will(TelnetOption),
    /// Indicate the server's refusal to use the given telnet option
    Wont(TelnetOption),
    /// Pass arbitrary bytes to the client
    PassThrough(Vec<u8>),
    /// Try to Enable Mouse Support
    EnableMouse,
    /// Try to Disable Cursor Support
    DisableMouse,
}

/// This codec parses an incoming stream of data as a series of terminal events.
#[derive(Default)]
pub struct TelnetCodec(());

impl TelnetCodec {
    pub fn new() -> Self {
        Default::default()
    }

    /// Convenience function to create a new framed stream
    pub fn framed<T>(t: T) -> tokio_codec::Framed<T, Self>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite,
    {
        Self::new().framed(t)
    }
}

const ENABLE_MOUSE: &[u8] = b"\x1B[?1000h\x1b[?1002h\x1b[?1015h\x1b[?1006h";
const DISABLE_MOUSE: &[u8] = b"\x1B[?1006l\x1b[?1015l\x1b[?1002l\x1b[?1000l";

fn encode(bytes: &mut BytesMut, byte: u8, opt: TelnetOption) {
    bytes.extend_from_slice(&[IAC, byte, opt as u8])
}

impl Encoder for TelnetCodec {
    type Item = ServerEvents;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            ServerEvents::Dont(opt) => encode(dst, DONT, opt),
            ServerEvents::Do(opt) => encode(dst, DO, opt),
            ServerEvents::Wont(opt) => encode(dst, WONT, opt),
            ServerEvents::Will(opt) => encode(dst, WILL, opt),
            ServerEvents::EnableMouse => dst.extend_from_slice(ENABLE_MOUSE),
            ServerEvents::DisableMouse => dst.extend_from_slice(DISABLE_MOUSE),

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

fn consume_event(
    bytes: &mut BytesMut,
    take: usize,
    event: ClientEvents,
) -> Result<Option<ClientEvents>, Error> {
    let _ = bytes.split_to(take);
    Ok(Some(event))
}

fn get_opt(opt: u8) -> Result<TelnetOption, Error> {
    TelnetOption::from_u8(opt).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("unknown telnet option {}", opt),
        )
    })
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
                (Some(IAC), _) => unimplemented!("escape code"),
                // We need more
                (Some(_), None) => Ok(None),
                // (Some(IAC), _) => consume_event!(bytes, 2, ClientEvents::Byte(IAC)),
                (Some(WILL), Some(opt)) => {
                    consume_event(bytes, 3, ClientEvents::Will(get_opt(opt)?))
                }
                (Some(WONT), Some(opt)) => {
                    consume_event(bytes, 3, ClientEvents::Wont(get_opt(opt)?))
                }
                (Some(DONT), Some(opt)) => {
                    consume_event(bytes, 3, ClientEvents::Dont(get_opt(opt)?))
                }
                (Some(DO), Some(opt)) => consume_event(bytes, 3, ClientEvents::Do(get_opt(opt)?)),
                (Some(SB), Some(opt)) => match_se(get_opt(opt)?, bytes),

                (Some(byte), _) => Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unknown IAC code {:02}", byte),
                )),
                _ => unreachable!(),
            }
        } else {
            // TODO: can we get rid of this?
            let bytes2 = bytes.clone();
            let mut iter = bytes2.bytes().skip(1);
            termion::event::parse_event(bytes[0], &mut iter)
                .and_then(|evt| {
                    bytes.clear();
                    bytes.extend(BytesMut::from_iter(iter.filter_map(Result::ok)));
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

/// Grab everything until we see an IAC SE sequence
fn match_se(
    opt: TelnetOption,
    bytes: &mut BytesMut,
) -> Result<Option<ClientEvents>, std::io::Error> {
    // Skip over IAC SB <protocol>
    let index = match bytes.iter().skip(3).position(|b| *b == IAC) {
        Some(idx) => idx + 3,
        None => return Ok(None),
    };

    match bytes.get(index + 1).cloned() {
        Some(SE) => (),
        // TODO: is this allowed?
        Some(byte) => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("expected {:02x}, got {:02x}", SE, byte),
            ));
        }
        None => return Ok(None),
    };

    // Remainder starts after IAC SE
    let payload = bytes.split_to(index + 2).freeze();

    let event = parse_suboption(opt, payload[3..index].to_vec())?;
    Ok(Some(event))
}

/// If we know this suboption, parse it into an event. Otherwise, return the raw bytes
fn parse_suboption(opt: TelnetOption, payload: Vec<u8>) -> Result<ClientEvents, Error> {
    match opt {
        TelnetOption::WindowSize => match *payload.as_slice() {
            [w0, w1, h0, h1] => {
                let h = u16::from_be_bytes([h0, h1]);
                let w = u16::from_be_bytes([w0, w1]);
                Ok(ClientEvents::ResizeEvent(h, w))
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "expected 4 byte payload for WindowSize, got {}",
                    payload.len()
                ),
            )),
        },
        _ => Ok(ClientEvents::RawSuboption(opt, payload)),
    }
}
