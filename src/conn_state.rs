use bytes::Buf;

use rand::{thread_rng, Rng};

use std::collections::VecDeque;
use std::io::Cursor;
use std::mem;

use hex;

use super::{QuicError, QuicResult, QUIC_VERSION};
use codec::Codec;
use crypto::Secret;
use frame::{Ack, AckFrame, CloseFrame, Frame, PaddingFrame, PathFrame, CryptoFrame};
use packet::{Header, LongType, PartialDecode, ShortType};
use parameters::{ClientTransportParameters, ServerTransportParameters, TransportParameters};
use streams::{Dir, Streams};
use handshake;
use types::{ConnectionId, Side, GENERATED_CID_LENGTH};

pub struct ConnectionState<T> {
    side: Side,
    state: State,
    local: PeerData,
    remote: PeerData,
    dst_pn: u32,
    src_pn: u32,
    secret: Secret,
    prev_secret: Option<Secret>,
    pub streams: Streams,
    queue: VecDeque<Vec<u8>>,
    control: VecDeque<Frame>,
    handshake: T,
    pmtu: usize,
}

fn recover_packet_number(current : u32, pn : u32, t : ShortType) -> u32 {
    let mask = match t {
        ShortType::One  => 0xffff_ff00,
        ShortType::Two  => 0xffff_0000,
        ShortType::Four => 0x0000_0000,
    };

    let new = (current & mask) | pn;
    let off = (mask & 0xffff_ffff) + 1;
    return if new < current {
        new + off
    } else {
        new
    }
}

impl<T> ConnectionState<T>
where
    T: handshake::Session + handshake::QuicSide,
{
    pub fn new(handshake: T, secret: Option<Secret>) -> Self {
        let mut rng = thread_rng();
        let dst_cid = rng.gen();
        let side    = handshake.side();

        let secret = if side == Side::Client {
            debug_assert!(secret.is_none());
            Secret::Handshake(dst_cid)
        } else if let Some(secret) = secret {
            secret
        } else {
            panic!("need secret for client conn_state");
        };

        let local = PeerData::new(rng.gen());
        let (num_recv_bidi, num_recv_uni) = (
            u64::from(local.params.max_streams_bidi),
            u64::from(local.params.max_stream_id_uni),
        );
        let (max_recv_bidi, max_recv_uni) = if side == Side::Client {
            (1 + 4 * num_recv_bidi, 3 + 4 * num_recv_uni)
        } else {
            (4 * num_recv_bidi, 1 + 4 * num_recv_uni)
        };

        let mut streams = Streams::new(side);
        streams.update_max_id(max_recv_bidi);
        streams.update_max_id(max_recv_uni);

        ConnectionState {
            handshake,
            side,
            state: State::Start,
            remote: PeerData::new(dst_cid),
            local,
            src_pn: rng.gen(),
            dst_pn: 0,
            secret,
            prev_secret: None,
            streams,
            queue: VecDeque::new(),
            control: VecDeque::new(),
            pmtu: IPV6_MIN_MTU,
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.state {
            State::Connected => false,
            _ => true,
        }
    }

    pub fn queued(&mut self) -> QuicResult<Option<&Vec<u8>>> {
        self.queue_packet()?;
        Ok(self.queue.front())
    }

    pub fn pop_queue(&mut self) {
        self.queue.pop_front();
    }

    pub fn pick_unused_cid<F>(&mut self, is_used: F) -> ConnectionId
    where
        F: Fn(ConnectionId) -> bool,
    {
        while is_used(self.local.cid) {
            self.local.cid = thread_rng().gen();
        }
        self.local.cid
    }

    pub(crate) fn set_secret(&mut self, secret: Secret) {
        let old = mem::replace(&mut self.secret, secret);
        self.prev_secret = Some(old);
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn queue_packet(&mut self) -> QuicResult<()> {

        let (dst_cid, src_cid) = (self.remote.cid, self.local.cid);
        debug_assert_eq!(src_cid.len, GENERATED_CID_LENGTH);
        let number = self.src_pn;
        self.src_pn += 1;

        println!("debug : queue packet, src_pn = {}", self.src_pn);

        let (ptype, new_state) = match self.state {
            State::Connected => (None, self.state),
            State::Handshaking => (Some(LongType::Handshake), self.state),
            State::InitialSent => (Some(LongType::Handshake), State::Handshaking),
            State::Start => if self.side == Side::Client {
                (Some(LongType::Initial), State::InitialSent)
            } else {
                (Some(LongType::Handshake), State::Handshaking)
            }
            State::ConfirmHandshake => (Some(LongType::Handshake), State::ConfirmHandshake),
        };

        let header_len = match ptype {
            Some(_) => (12 + (dst_cid.len + src_cid.len) as usize),
            None => (3 + dst_cid.len as usize),
        };

        let secret = if let Some(LongType::Handshake) = ptype {
            if let Some(ref secret @ Secret::Handshake(_)) = self.prev_secret {
                secret
            } else {
                &self.secret
            }
        } else {
            &self.secret
        };

        let key = secret.build_key(self.side);
        let tag_len = key.algorithm().tag_len();

        let mut buf = vec![0u8; self.pmtu];
        let payload_len = {
            let mut write = Cursor::new(&mut buf[header_len..self.pmtu - tag_len]);
            while let Some(frame) = self.control.pop_front() {
                println!("debug :   control frame {:?}", frame);
                frame.encode(&mut write);
            }
            self.streams.poll_send(&mut write);

            let mut payload_len = write.position() as usize;
            let initial_min_size = 1200 - header_len - tag_len;
            if ptype == Some(LongType::Initial) && payload_len < initial_min_size {
                Frame::Padding(PaddingFrame(initial_min_size - payload_len)).encode(&mut write);
                payload_len = initial_min_size;
            }
            payload_len
        };

        if payload_len == 0 {
            return Ok(());
        }

        let header = match ptype {
            Some(ltype) => Header::Long {
                ptype: ltype,
                version: QUIC_VERSION,
                dst_cid,
                src_cid,
                len: (payload_len + tag_len) as u64,
                number,
            },
            None => Header::Short {
                key_phase: false,
                ptype: ShortType::Two,
                dst_cid,
                number,
            },
        };

        println!("{:?}", header);

        {
            let mut write = Cursor::new(&mut buf[..header_len]);
            header.encode(&mut write);
        }

        let out_len = {
            let (header_buf, mut payload) = buf.split_at_mut(header_len);
            let mut in_out = &mut payload[..payload_len + tag_len];
            key.encrypt(number, &header_buf, in_out, tag_len)?
        };

        buf.truncate(header_len + out_len);
        self.queue.push_back(buf);
        self.state = new_state;
        Ok(())
    }

    pub(crate) fn handle(&mut self, buf: &mut [u8]) -> QuicResult<()> {
        println!("debug : handle packet");
        println!("  buf = {}", hex::encode(&buf));
        let pdecode = PartialDecode::new(buf)?;
        self.handle_partial(pdecode)
    }

    pub(crate) fn handle_partial(&mut self, partial: PartialDecode) -> QuicResult<()> {
        let PartialDecode {
            header,
            header_len,
            buf,
        } = partial;

        let key = {
            let secret = &self.secret;
            secret.build_key(self.side.other())
        };

        println!("debug :  state = {:?}", &self.state);

        println!("{:?}", header);

        let payload = match header {
            Header::Long { number, .. } | Header::Short { number, .. } => {
                let (header_buf, payload_buf) = buf.split_at_mut(header_len);

                let number = match header {
                    Header::Short { ptype, .. } =>
                        recover_packet_number(self.dst_pn, number, ptype),
                    _ => number,
                };

                let decrypted = key.decrypt(number, &header_buf, payload_buf)?;

                self.dst_pn = number;

                // implicit confirmation

                match self.state {
                    State::ConfirmHandshake => self.state = State::Connected,
                    _ => (),
                }

                let mut read = Cursor::new(decrypted);
                let mut payload = Vec::new();
                while read.has_remaining() {
                    let frame = Frame::decode(&mut read)?;
                    payload.push(frame);
                }
                payload
            }
            Header::Negotiation { .. } => vec![],
        };

        self.handle_packet(header, payload)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    fn handle_packet(&mut self, header: Header, payload: Vec<Frame>) -> QuicResult<()> {
        let (dst_cid, number) = match header {
            Header::Long {
                dst_cid,
                src_cid,
                number,
                ..
            } => match self.state {
                State::Start | State::InitialSent => {
                    self.remote.cid = src_cid;
                    (dst_cid, number)
                }
                _ => (dst_cid, number),
            },
            Header::Short {
                dst_cid, number, ..
            } => if let State::Connected = self.state {
                (dst_cid, number)
            } else {
                return Err(QuicError::General(format!(
                    "{:?} received short header in {:?} state",
                    self.side, self.state
                )));
            },
            Header::Negotiation { .. } => {
                return Err(QuicError::General(
                    "negotiation packet not handled by connections".into(),
                ));
            }
        };

        if self.state != State::Start && dst_cid != self.local.cid {
            return Err(QuicError::General(format!(
                "invalid destination CID {:?} received (expected {:?} in state {:?})",
                dst_cid, self.local.cid, self.state
            )));
        }

        let mut send_ack = false;
        for frame in &payload {
            println!("debug : decoded frame:");
            println!("debug :   {:?}", frame);
            match frame {
                Frame::Crypto(f) => {
                    self.handle_handshake_message(&f.payload);
                }
                Frame::Stream(f) => {
                    assert!(self.state == State::Connected);
                    send_ack = true;
                    self.streams.received(f)?;
                }
                Frame::PathChallenge(PathFrame(token)) => {
                    send_ack = true;
                    self.control
                        .push_back(Frame::PathResponse(PathFrame(*token)));
                }
                Frame::ApplicationClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ApplicationClose(*code, reason.clone()));
                }
                Frame::ConnectionClose(CloseFrame { code, reason }) => {
                    return Err(QuicError::ConnectionClose(*code, reason.clone()));
                }
                Frame::PathResponse(_) | Frame::Ping | Frame::StreamIdBlocked(_) => {
                    send_ack = true;
                }
                Frame::Ack(_) | Frame::Padding(_) => {}
            }
        }

        if send_ack {
            self.control.push_back(Frame::Ack(AckFrame {
                largest: number,
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }));
        }

        Ok(())
    }

    fn handle_handshake_message(&mut self, msg : &[u8]) -> QuicResult<()> {

        println!("debug : handle handshake message:");
        println!("debug :   length = {}", msg.len());

        let (new_msg, new_secret) = self.handshake.process_handshake_message(msg)?;

        // process new key material

        if let Some(secret) = new_secret {


            /* TODO
            let params = match self.tls.get_quic_transport_parameters() {
                None => {
                    return Err(QuicError::General(
                        "no transport parameters received".into(),
                    ));
                }
                Some(bytes) => {
                    let mut read = Cursor::new(bytes);
                    if self.side == Side::Client {
                        ServerTransportParameters::decode(&mut read)?.parameters
                    } else {
                        ClientTransportParameters::decode(&mut read)?.parameters
                    }
                }
            };

            mem::replace(&mut self.remote.params, params);
            */

            let (num_send_bidi, num_send_uni) = (
                u64::from(self.remote.params.max_streams_bidi),
                u64::from(self.remote.params.max_stream_id_uni),
            );

            let (max_send_bidi, max_send_uni) = if self.side == Side::Server {
                (1 + 4 * num_send_bidi, 3 + 4 * num_send_uni)
            } else {
                (4 * num_send_bidi, 1 + 4 * num_send_uni)
            };
            self.streams.update_max_id(max_send_bidi);
            self.streams.update_max_id(max_send_uni);

            // update secret

            self.set_secret(secret);

            // update state

            match self.side {
                Side::Client => {
                    self.state = State::Connected;
                    self.control.push_back(Frame::Padding(PaddingFrame(1))); // TODO : less hacky
                },
                Side::Server => {
                    self.state = State::ConfirmHandshake;
                }
            };
        }

        // send new message

        if let Some(msg) = new_msg {
            assert!(self.is_handshaking());
            println!("debug : send handshake message");
            println!("debug :   msg = {} ", hex::encode(&msg));
            self.control.push_back(Frame::Crypto(CryptoFrame {
                len     : Some(msg.len() as u64),
                payload : msg,
            }));
        }

        Ok(())
    }
}

impl ConnectionState<handshake::ClientSession> {
    pub(crate) fn initial(&mut self) -> QuicResult<()> {
        println!("debug : create initial handshake packet");
        let msg = self.handshake.create_handshake_request()?;
        debug_assert!(msg.len() < (1 << 16));
        self.control.push_back(Frame::Crypto(CryptoFrame{
            len     : Some(msg.len() as u64),
            payload : msg,
        }));
        Ok(())
    }
}

pub struct PeerData {
    pub cid: ConnectionId,
    pub params: TransportParameters,
}

impl PeerData {
    pub fn new(cid: ConnectionId) -> Self {
        PeerData {
            cid,
            params: TransportParameters::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Start,
    InitialSent,
    Handshaking,
    ConfirmHandshake,
    Connected,
}

const IPV6_MIN_MTU: usize = 1232;
