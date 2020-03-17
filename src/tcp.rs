//! Handles parsing of TCP headers

use nom::bits;
use nom::error::ErrorKind;
use nom::number;
use nom::sequence;
use nom::{Err, IResult, Needed};

// TCP Header Format
//
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Source Port          |       Destination Port        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Sequence Number                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Acknowledgment Number                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Data |           |U|A|P|R|S|F|                               |
//   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//   |       |           |G|K|H|T|N|N|                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Checksum            |         Urgent Pointer        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             data                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// TCP Flags:
//    URG:  Urgent Pointer field significant
//    ACK:  Acknowledgment field significant
//    PSH:  Push Function
//    RST:  Reset the connection
//    SYN:  Synchronize sequence numbers
//    FIN:  No more data from sender

const END_OF_OPTIONS: u8 = 0;
const NO_OP: u8 = 1;
const MSS: u8 = 2;
const WINDOW_SCALE: u8 = 3;
const SACK_PERMITTED: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TcpOption {
    EndOfOptions,
    NoOperation,
    MaximumSegmentSize(MaximumSegmentSize),
    WindowScale(WindowScale),
    SackPermitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MaximumSegmentSize {
    pub mss: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowScale {
    pub scaling: u8,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TcpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_no: u32,
    pub ack_no: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flag_urg: bool,
    pub flag_ack: bool,
    pub flag_psh: bool,
    pub flag_rst: bool,
    pub flag_syn: bool,
    pub flag_fin: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Vec<TcpOption>>,
}

fn dataof_res_flags(input: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    bits::bits::<_, _, (_, ErrorKind), _, _>(sequence::tuple((
        bits::streaming::take(4u8),
        bits::streaming::take(6u8),
        bits::streaming::take(6u8),
    )))(input)
}

fn tcp_parse(input: &[u8]) -> IResult<&[u8], TcpHeader> {
    let (input, source_port) = number::streaming::be_u16(input)?;
    let (input, dest_port) = number::streaming::be_u16(input)?;
    let (input, sequence_no) = number::streaming::be_u32(input)?;
    let (input, ack_no) = number::streaming::be_u32(input)?;
    let (input, dataof_res_flags) = dataof_res_flags(input)?;
    let (input, window) = number::streaming::be_u16(input)?;
    let (input, checksum) = number::streaming::be_u16(input)?;
    let (input, urgent_pointer) = number::streaming::be_u16(input)?;

    Ok((
        input,
        TcpHeader {
            source_port,
            dest_port,
            sequence_no,
            ack_no,
            data_offset: dataof_res_flags.0,
            reserved: dataof_res_flags.1,
            flag_urg: dataof_res_flags.2 & 0b10_0000 == 0b10_0000,
            flag_ack: dataof_res_flags.2 & 0b01_0000 == 0b01_0000,
            flag_psh: dataof_res_flags.2 & 0b00_1000 == 0b00_1000,
            flag_rst: dataof_res_flags.2 & 0b00_0100 == 0b00_0100,
            flag_syn: dataof_res_flags.2 & 0b00_0010 == 0b00_0010,
            flag_fin: dataof_res_flags.2 & 0b00_0001 == 0b00_0001,
            window,
            checksum,
            urgent_pointer,
            options: None,
        },
    ))
}

fn tcp_parse_option(input: &[u8]) -> IResult<&[u8], TcpOption> {
    match number::streaming::be_u8(input)? {
        (input, END_OF_OPTIONS) => Ok((input, TcpOption::EndOfOptions)),
        (input, NO_OP) => Ok((input, TcpOption::NoOperation)),
        (input, MSS) => {
            let (input, _len) = number::streaming::be_u8(input)?;
            let (input, mss) = number::streaming::be_u16(input)?;
            Ok((
                input,
                TcpOption::MaximumSegmentSize(MaximumSegmentSize { mss }),
            ))
        }
        (input, WINDOW_SCALE) => {
            let (input, _len) = number::streaming::be_u8(input)?;
            let (input, scaling) = number::streaming::be_u8(input)?;
            Ok((input, TcpOption::WindowScale(WindowScale { scaling })))
        }
        (input, SACK_PERMITTED) => {
            let (input, _len) = number::streaming::be_u8(input)?;
            Ok((input, TcpOption::SackPermitted))
        }
        _ => Err(Err::Failure((input, ErrorKind::Switch))),
    }
}

fn tcp_parse_options(i: &[u8]) -> IResult<&[u8], Vec<TcpOption>> {
    let mut left = i;
    let mut options: Vec<TcpOption> = vec![];
    loop {
        match tcp_parse_option(left) {
            Ok((l, opt)) => {
                left = l;
                options.push(opt);

                if let TcpOption::EndOfOptions = opt {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok((left, options))
}

pub fn parse_tcp_header(i: &[u8]) -> IResult<&[u8], TcpHeader> {
    match tcp_parse(i) {
        Ok((left, mut tcp_header)) => {
            // Offset in words (at least 5)
            if tcp_header.data_offset > 5 {
                let options_length = ((tcp_header.data_offset - 5) * 4) as usize;
                if options_length <= left.len() {
                    if let Ok((_, options)) = tcp_parse_options(&left[0..options_length]) {
                        tcp_header.options = Some(options);
                        return Ok((&left[options_length..], tcp_header));
                    }
                    Ok((&left[options_length..], tcp_header))
                } else {
                    Err(Err::Incomplete(Needed::Size(options_length - left.len())))
                }
            } else {
                Ok((left, tcp_header))
            }
        }

        e => e,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn test_tcp_parse() {
        let bytes = [
            0xc2, 0x1f, /* Source port */
            0x00, 0x50, /* Dest port */
            0x0f, 0xd8, 0x7f, 0x4c, /* Seq no */
            0xeb, 0x2f, 0x05, 0xc8, /* Ack no */
            0x50, 0x18, 0x01, 0x00, /* Window */
            0x7c, 0x29, /* Checksum */
            0x00, 0x00, /* Urgent pointer */
        ];

        let expectation = TcpHeader {
            source_port: 49695,
            dest_port: 80,
            sequence_no: 0x0fd87f4c,
            ack_no: 0xeb2f05c8,
            data_offset: 5,
            reserved: 0,
            flag_urg: false,
            flag_ack: true,
            flag_psh: true,
            flag_rst: false,
            flag_syn: false,
            flag_fin: false,
            window: 256,
            checksum: 0x7c29,
            urgent_pointer: 0,
            options: None,
        };

        assert_eq!(parse_tcp_header(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
