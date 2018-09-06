use bytes::{Buf, BufMut};

use codec::{BufLen, Codec, VarLen};

use std::str;

use super::{QuicError, QuicResult};

const CRYPTO_FRAME_ID : u8 = 0x18; // see draft-13

#[derive(Debug, PartialEq)]
pub enum Frame {
    Ack(AckFrame),
    ApplicationClose(CloseFrame),
    ConnectionClose(CloseFrame),
    Padding(PaddingFrame),
    PathChallenge(PathFrame),
    PathResponse(PathFrame),
    Ping,
    Stream(StreamFrame),
    StreamIdBlocked(StreamIdBlockedFrame),
    Crypto(CryptoFrame),
}

impl BufLen for Frame {
    fn buf_len(&self) -> usize {
        match self {
            Frame::Ack(f) => f.buf_len(),
            Frame::Crypto(f) => 1 + f.buf_len(),
            Frame::ApplicationClose(f) => 1 + f.buf_len(),
            Frame::ConnectionClose(f) => 1 + f.buf_len(),
            Frame::Padding(f) => f.buf_len(),
            Frame::PathChallenge(f) => 1 + f.buf_len(),
            Frame::PathResponse(f) => 1 + f.buf_len(),
            Frame::Ping => 1,
            Frame::Stream(f) => f.buf_len(),
            Frame::StreamIdBlocked(f) => 1 + f.buf_len(),
        }
    }
}

impl Codec for Frame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        match self {
            Frame::Ack(f) => f.encode(buf),
            Frame::ApplicationClose(f) => {
                buf.put_u8(0x03);
                f.encode(buf)
            }
            Frame::ConnectionClose(f) => {
                buf.put_u8(0x02);
                f.encode(buf)
            }
            Frame::Padding(f) => f.encode(buf),
            Frame::PathChallenge(f) => {
                buf.put_u8(0x0e);
                f.encode(buf)
            }
            Frame::PathResponse(f) => {
                buf.put_u8(0x0f);
                f.encode(buf)
            }
            Frame::Ping => buf.put_u8(0x07),
            Frame::Stream(f) => f.encode(buf),
            Frame::StreamIdBlocked(f) => {
                buf.put_u8(0x0a);
                f.encode(buf)
            }
            Frame::Crypto(f) => {
                buf.put_u8(CRYPTO_FRAME_ID);
                f.encode(buf)
            }
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        Ok(match buf.bytes()[0] {
            v if v >= 0x10 && v < 0x18
                => Frame::Stream(StreamFrame::decode(buf)?),
            0x02 => Frame::ConnectionClose({
                buf.get_u8();
                CloseFrame::decode(buf)?
            }),
            0x03 => Frame::ApplicationClose({
                buf.get_u8();
                CloseFrame::decode(buf)?
            }),
            0x07 => {
                buf.get_u8();
                Frame::Ping
            }
            0x0a => Frame::StreamIdBlocked({
                buf.get_u8();
                StreamIdBlockedFrame::decode(buf)?
            }),
            CRYPTO_FRAME_ID => Frame::Crypto({
                buf.get_u8();
                CryptoFrame::decode(buf)?
            }),
            0x0d => Frame::Ack(AckFrame::decode(buf)?),
            0x0e => Frame::PathChallenge({
                buf.get_u8();
                PathFrame::decode(buf)?
            }),
            0x0f => Frame::PathResponse({
                buf.get_u8();
                PathFrame::decode(buf)?
            }),
            0 => Frame::Padding(PaddingFrame::decode(buf)?),
            v => {
                return Err(QuicError::DecodeError(format!(
                    "unimplemented decoding for frame type {}",
                    v
                )))
            }
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct StreamFrame {
    pub id: u64,
    pub fin: bool,
    pub offset: u64,
    pub len: Option<u64>,
    pub data: Vec<u8>,
}

impl BufLen for StreamFrame {
    fn buf_len(&self) -> usize {
        1 + VarLen(self.id).buf_len() + if self.offset > 0 {
            VarLen(self.offset).buf_len()
        } else {
            0
        } + self.len.map(VarLen).buf_len() + self.data.len()
    }
}

impl Codec for StreamFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let has_offset = if self.offset > 0 { 0x04 } else { 0 };
        let has_len = if self.len.is_some() { 0x02 } else { 0 };
        let is_fin = if self.fin { 0x01 } else { 0 };
        buf.put_u8(0x10 | has_offset | has_len | is_fin);
        VarLen(self.id).encode(buf);
        if self.offset > 0 {
            VarLen(self.offset).encode(buf);
        }
        if let Some(len) = self.len {
            VarLen(len).encode(buf);
        }
        buf.put_slice(&self.data);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let first = buf.get_u8();
        let id = VarLen::decode(buf)?.0;
        let offset = if first & 0x04 > 0 {
            VarLen::decode(buf)?.0
        } else {
            0
        };

        let rem = buf.remaining() as u64;
        let (len, consume) = match first & 0x02 {
            0 => (None, rem),
            _ => {
                let len = VarLen::decode(buf)?.0;
                if len > rem {
                    return Err(
                        QuicError::DecodeError("length too great".to_string())
                    );
                }
                (Some(len), len)
            }
        };

        let mut data = vec![0u8; consume as usize];
        buf.copy_to_slice(&mut data);

        Ok(StreamFrame {
            id,
            fin: first & 0x01 > 0,
            offset,
            len,
            data,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CryptoFrame {
    pub offset  : u64,
    pub length  : u64,
    pub payload : Vec<u8>,
}

impl BufLen for CryptoFrame {
    fn buf_len(&self) -> usize {
        1 +
        VarLen(self.offset).buf_len() +
        VarLen(self.length).buf_len() +
        self.payload.len()
    }
}

impl Codec for CryptoFrame {
    /* Flags:
     *  has_offset : The offset should always be zero, hence can be omitted entirely
     */
    fn encode<T: BufMut>(&self, buf: &mut T) {
        VarLen(self.offset).encode(buf);
        VarLen(self.length).encode(buf);
        buf.put_slice(&self.payload);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let offset = VarLen::decode(buf)?.0;
        let length = VarLen::decode(buf)?.0;

        if length > buf.remaining() as u64 {
            return Err(QuicError::DecodeError("length is too great".to_string()));
        }

        // copy payload into frame

        let mut payload = vec![0u8; length as usize];
        buf.copy_to_slice(&mut payload);
        Ok(CryptoFrame {offset, length, payload})
    }
}

#[derive(Debug, PartialEq)]
pub struct AckFrame {
    pub largest: u32,
    pub ack_delay: u64,
    pub blocks: Vec<Ack>,
}

impl BufLen for AckFrame {
    fn buf_len(&self) -> usize {
        1 + VarLen(u64::from(self.largest)).buf_len() + VarLen(self.ack_delay).buf_len()
            + VarLen((self.blocks.len() - 1) as u64).buf_len()
            + self.blocks
                .iter()
                .map(|v| VarLen(v.value()).buf_len())
                .sum::<usize>()
    }
}

impl Codec for AckFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u8(0x0d);
        VarLen(u64::from(self.largest)).encode(buf);
        VarLen(self.ack_delay).encode(buf);
        VarLen((self.blocks.len() - 1) as u64).encode(buf);
        for ack in &self.blocks {
            VarLen(ack.value()).encode(buf);
        }
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let _ = buf.get_u8();
        let largest = VarLen::decode(buf)?.0 as u32;
        let ack_delay = VarLen::decode(buf)?.0;
        let count = VarLen::decode(buf)?.0;
        debug_assert_eq!(count % 2, 0);

        let mut blocks = vec![];
        for i in 0..count + 1 {
            blocks.push(if i % 2 == 0 {
                Ack::Ack(VarLen::decode(buf)?.0)
            } else {
                Ack::Gap(VarLen::decode(buf)?.0)
            });
        }

        Ok(AckFrame {
            largest,
            ack_delay,
            blocks,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Ack {
    Ack(u64),
    Gap(u64),
}

impl Ack {
    fn value(&self) -> u64 {
        match *self {
            Ack::Ack(v) => v,
            Ack::Gap(v) => v,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct CloseFrame {
    pub(crate) code: u16,
    pub(crate) reason: String,
}

impl BufLen for CloseFrame {
    fn buf_len(&self) -> usize {
        2 + VarLen(self.reason.len() as u64).buf_len() + self.reason.len()
    }
}

impl Codec for CloseFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u16_be(self.code);
        VarLen(self.reason.len() as u64).encode(buf);
        buf.put_slice(self.reason.as_bytes());
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let code = buf.get_u16_be();
        let len = VarLen::decode(buf)?.0 as usize;
        let reason = {
            let bytes = buf.bytes();
            str::from_utf8(&bytes[..len]).unwrap()
        }.to_string();
        buf.advance(len);
        Ok(CloseFrame { code, reason })
    }
}

#[derive(Debug, PartialEq)]
pub struct PathFrame(pub [u8; 8]);

impl BufLen for PathFrame {
    fn buf_len(&self) -> usize {
        8
    }
}

impl Codec for PathFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_slice(&self.0);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let mut bytes = [0; 8];
        buf.copy_to_slice(&mut bytes);
        Ok(PathFrame(bytes))
    }
}

#[derive(Debug, PartialEq)]
pub struct StreamIdBlockedFrame(pub u64);

impl BufLen for StreamIdBlockedFrame {
    fn buf_len(&self) -> usize {
        VarLen(self.0).buf_len()
    }
}

impl Codec for StreamIdBlockedFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        VarLen(self.0).encode(buf)
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        Ok(StreamIdBlockedFrame(VarLen::decode(buf)?.0))
    }
}

#[derive(Debug, PartialEq)]
pub struct PaddingFrame(pub usize);

impl BufLen for PaddingFrame {
    fn buf_len(&self) -> usize {
        self.0
    }
}

impl Codec for PaddingFrame {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let padding = vec![0; self.0];
        buf.put_slice(&padding);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let size = buf.bytes().iter().take_while(|b| **b == 0).count();
        buf.advance(size);
        Ok(PaddingFrame(size))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Buf;
    use codec::{BufLen, Codec};
    use std::io::Cursor;

    #[test]
    fn test_padding_roundtrip() {
        let bytes = b"\x00\x00\x00\x00\x01";
        let frame = {
            let mut read = Cursor::new(&bytes);
            let frame = super::Frame::decode(&mut read).unwrap();
            assert_eq!(read.bytes(), b"\x01");
            frame
        };
        assert_eq!(frame, super::Frame::Padding(super::PaddingFrame(4)));

        let mut buf = vec![0u8; 16];
        frame.encode(&mut buf);
        assert_eq!(&bytes[..4], &buf[..4]);
    }

    #[test]
    fn test_ack_roundtrip() {
        let obj = super::Frame::Ack(super::AckFrame {
            largest: 485971334,
            ack_delay: 0,
            blocks: vec![super::Ack::Ack(0)],
        });
        let bytes = b"\x0d\x9c\xf7\x55\x86\x00\x00\x00";
        assert_eq!(obj.buf_len(), bytes.len());

        let mut buf = Vec::with_capacity(64);
        obj.encode(&mut buf);
        assert_eq!(&buf, bytes);

        let mut read = Cursor::new(bytes);
        let decoded = super::Frame::decode(&mut read).unwrap();
        assert_eq!(decoded, obj);
    }

    #[test]
    fn test_crypto_round_trip() {
        let payload = b"\x0d\x9c\xf7\x55\x86\x00\x00\x00";
        let obj = super::Frame::Crypto(super::CryptoFrame {
            offset  : 0,
            length  : payload.len() as u64,
            payload : payload.to_vec(),
        });
        let bytes = b"\x0b\x00\x08\x0d\x9c\xf7\x55\x86\x00\x00\x00";
        assert_eq!(obj.buf_len(), bytes.len());

        let mut buf = Vec::with_capacity(64);
        obj.encode(&mut buf);
        println!("{:?}", buf);
        assert_eq!(buf.len(), obj.buf_len());


        let mut read = Cursor::new(bytes);
        let decoded = super::Frame::decode(&mut read).unwrap();
        assert_eq!(decoded, obj);
    }
}
