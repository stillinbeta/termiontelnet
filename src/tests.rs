use super::*;
use super::{ClientEvents, ServerEvents, TelnetOption::*};
extern crate tokio_mockstream;
use tokio_mockstream::MockStream;

use termion::event::{Event, Key};

// Actual data, captured by pcap.
const LINEMODE_SUBOPT: &[u8] = &[
    0xff, 0xfa, 0x22, 0x03, 0x01, 0x00, 0x00, 0x03, 0x62, 0x03, 0x04, 0x02, 0x0f, 0x05, 0x00, 0x00,
    0x07, 0x62, 0x1c, 0x08, 0x02, 0x04, 0x09, 0x42, 0x1a, 0x0a, 0x02, 0x7f, 0x0b, 0x02, 0x15, 0x0f,
    0x02, 0x11, 0x10, 0x02, 0x13, 0x11, 0x00, 0x00, 0x12, 0x00, 0x00, 0xff, 0xf0,
];

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
    use ServerEvents::*;

    assert_encodes_to!(Dont(WindowSize), &[IAC, DONT, 31]);
    assert_encodes_to!(Do(WindowSize), &[IAC, DO, 31]);

    assert_encodes_to!(Dont(Echo), &[IAC, DONT, 1]);
    assert_encodes_to!(Do(Echo), &[IAC, DO, 1]);

    assert_encodes_to!(Dont(LineMode), &[IAC, DONT, 34]);
    assert_encodes_to!(ServerEvents::Do(LineMode), &[IAC, DO, 34]);
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
    use ClientEvents::*;

    assert_decodes_to!(&[IAC, WILL, 31], Will(WindowSize));
    assert_decodes_to!(&[IAC, WONT, 31], Wont(WindowSize));

    assert_decodes_to!(&[IAC, WILL, 1], Will(Echo));
    assert_decodes_to!(&[IAC, WONT, 1], Wont(Echo));

    assert_decodes_to!(&[IAC, WILL, 34], Will(LineMode));
    assert_decodes_to!(&[IAC, WONT, 34], Wont(LineMode));
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
    use ClientEvents::*;

    assert_decodes_to!(
        &[b'\x7f', IAC, WILL, 31, 0, IAC, SB, 31, 0, 80, 0, 40, IAC, SE, b'\x1B', b'[', b'A'],
        TermionEvent(Event::Key(Key::Backspace)),
        Will(WindowSize),
        TermionEvent(Event::Key(Key::Null)),
        ResizeEvent(40, 80),
        TermionEvent(Event::Key(Key::Up)),
    )
}

#[test]
fn decode_subline() {
    use ClientEvents::*;

    assert_decodes_to!(
        LINEMODE_SUBOPT,
        RawSuboption(
            LineMode,
            vec![
                0x03, 0x01, 0x00, 0x00, 0x03, 0x62, 0x03, 0x04, 0x02, 0x0f, 0x05, 0x00, 0x00, 0x07,
                0x62, 0x1c, 0x08, 0x02, 0x04, 0x09, 0x42, 0x1a, 0x0a, 0x02, 0x7f, 0x0b, 0x02, 0x15,
                0x0f, 0x02, 0x11, 0x10, 0x02, 0x13, 0x11, 0x00, 0x00, 0x12, 0x00, 0x00,
            ]
        ),
    )
}

#[test]
fn match_se_saves_rest() {
    let mut bytes = (&[IAC, SB, Echo as u8, 1, 2, 3, 4, 5, IAC, SE, 20, 21] as &[u8]).into();

    let extended = match_se(Echo, &mut bytes).unwrap().unwrap();
    assert_eq!(
        ClientEvents::RawSuboption(Echo, vec![1, 2, 3, 4, 5]),
        extended
    );

    assert_eq!(&[20, 21], bytes.as_ref());
}
