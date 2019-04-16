extern crate tokio;
extern crate tokio_codec;

extern crate bytes;

use bytes::BytesMut;
use tokio::io::Error;
use tokio_codec::{Decoder, Encoder};

pub enum IACEvents {
    IACWillNAWS,
    IACWontNAWS,
    IACDoNAWS,
    IACDontNAWS,
    ResizeEvent(u16, u16),
    PassThrough(Vec<u8>),
}

pub struct TermionCodec(());

impl TermionCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Encoder for TermionCodec {
    type Item = IACEvents;
    type Error = Error;

    fn encode(&mut self, _item: Self::Item, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl Decoder for TermionCodec {
    type Item = IACEvents;
    type Error = Error;

    fn decode(&mut self, _bytes: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        unimplemented!()
    }
}
