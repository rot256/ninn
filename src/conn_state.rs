use bytes::Buf;

use rand::{thread_rng, Rng};

use std::collections::VecDeque;
use std::io::Cursor;
use std::mem;

use hex;

use super::{QuicError, QuicResult, QUIC_VERSION};
use codec::Codec;
use frame::{Ack, AckFrame, CloseFrame, Frame, PaddingFrame, PathFrame, CryptoFrame};
use packet::{Header, LongType, PartialDecode, ShortType, reconstruct_packet_number};
use parameters::TransportParameters;
use streams::Streams;
use handshake;
use types::{ConnectionId, Side, GENERATED_CID_LENGTH};

use protector::{Protector, ProtectorHandshake, Protector1RTT, Secret};

const TAG_SIZE : usize = 16;

pub struct ConnectionState<T> {
    side: Side,
    state: State,
    local: PeerData,
    remote: PeerData,
    dst_pn: u64,
    src_pn: u64,

    protector: Box<Protector + Send>,
    protector_old: Option<Box<Protector + Send>>,

    pub streams: Streams,
    queue: VecDeque<Vec<u8>>,
    control: VecDeque<Frame>,
    handshake: T,
    pmtu: usize,

    protector_msg: Option<Vec<u8>>,

    // crypto

    crypto_offset: u64
}

impl<T> ConnectionState<T>
where
    T: handshake::Session + handshake::QuicSide,
{
    pub fn new(handshake: T, client_conn_id: Option<ConnectionId>) -> Self {
        let mut rng = thread_rng();
        let dst_cid = rng.gen();
        let side    = handshake.side();

        debug!("side           = {:?}", side);

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

        let hshake = match side {
            Side::Client => dst_cid,
            Side::Server => {
                if let Some(id) = client_conn_id {
                    id
                } else {
                    panic!("client connection id required for server instance");
                }
            }
        };

        let mut streams = Streams::new(side);
        streams.update_max_id(max_recv_bidi);
        streams.update_max_id(max_recv_uni);

        let src_pn : u64 = rng.gen();

        ConnectionState {
            handshake,
            side,
            state: State::Start,
            remote: PeerData::new(dst_cid),
            local,
            src_pn: src_pn & 0x0000_0000_ffff_ffff,
            dst_pn: 0,
            crypto_offset: 0,
            protector: Box::new(ProtectorHandshake::new(hshake, side)),
            protector_old: None,
            streams,
            queue: VecDeque::new(),
            control: VecDeque::new(),
            protector_msg: None,
            pmtu: IPV6_MIN_MTU,
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self.state {
            State::Connected => false,
            _                => true,
        }
    }

    pub fn queued(&mut self) -> QuicResult<Option<&Vec<u8>>> {

        // attempt to upgrade protection key

        if !self.is_handshaking() && self.protector_msg == None {
            self.protector_msg = self.protector.get_crypto_frame();
        }

        // coalesce frames into the packet

        self.queue_packet()?;

        // protector messages guaranteed to be sent

        self.protector_msg = None;
        self.protector.evolve();

        // return next packet

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

    pub(crate) fn set_rtt1_key(&mut self, secret: Secret) {
        debug!("installing RTT-1 protector");
        let old = mem::replace(
            &mut self.protector,
            Box::new(Protector1RTT::new(secret, self.side))
        );
        self.protector_old = Some(old);
    }

    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn queue_packet(&mut self) -> QuicResult<()> {

        let (dst_cid, src_cid) = (self.remote.cid, self.local.cid);
        debug_assert_eq!(src_cid.len, GENERATED_CID_LENGTH);

        let number = self.src_pn;

        // update state

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

        // select protector

        let ref protector = if let Some(LongType::Handshake) = ptype {
            if let Some(ref p) = self.protector_old {
                p
            } else {
                &self.protector
            }
        } else {
            &self.protector
        };

        // encode frames into buffer

        let mut buf = vec![0u8; self.pmtu];

        let header_len = match ptype {
            Some(_) => (12 + (dst_cid.len + src_cid.len) as usize),
            None => (3 + dst_cid.len as usize),
        };

        let payload_len = {

            let mut write = Cursor::new(
                &mut buf[header_len..self.pmtu - TAG_SIZE]
            );

            // 0. Future secrecy messages

            if let Some(ref msg) = self.protector_msg {
                debug!("encode future secrecy frame {:?}", msg);
                Frame::Crypto(CryptoFrame {
                    offset  : self.crypto_offset,
                    length  : msg.len() as u64,
                    payload : msg.to_vec(),
                }).encode(&mut write);
                self.crypto_offset += msg.len() as u64;
            }

            // 1. control messages

            while let Some(frame) = self.control.pop_front() {
                debug!("encode control frame {:?}", frame);
                frame.encode(&mut write);
            }

            // 2. stream / application data

            self.streams.poll_send(&mut write);

            let mut payload_len = write.position() as usize;
            let initial_min_size = 1200 - header_len - TAG_SIZE;
            if ptype == Some(LongType::Initial) && payload_len < initial_min_size {
                Frame::Padding(PaddingFrame(initial_min_size - payload_len)).encode(&mut write);
                payload_len = initial_min_size;
            }
            payload_len
        };

        if payload_len == 0 {
            return Ok(());
        }

        debug!("queue packet");
        debug!("     src_pn = {}", self.src_pn);
        debug!("       type = {:?}", ptype);
        debug!("  protector = {:?}", protector);

        // add header to buffer

        let header = match ptype {
            Some(ltype) => Header::Long {
                ptype: ltype,
                version: QUIC_VERSION,
                dst_cid,
                src_cid,
                len: (payload_len + TAG_SIZE) as u64,
                number: (number as u32),
            },
            None => Header::Short {
                key_phase: protector.key_phase(),
                ptype: ShortType::Two,
                dst_cid,
                number: (number as u32),
            },
        };

        {
            let mut write = Cursor::new(&mut buf[..header_len]);
            header.encode(&mut write);
        }

        // encrypt and authenticate packet

        let out_len = {
            let (header_buf, mut payload) = buf.split_at_mut(header_len);
            let mut in_out = &mut payload[..payload_len + TAG_SIZE];
            protector.encrypt(
                number,
                &header_buf,
                in_out,
                TAG_SIZE,
            )?
        };

        buf.truncate(header_len + out_len);

        debug!("      send = {}", hex::encode(&buf));

        self.queue.push_back(buf);
        self.state = new_state;
        self.src_pn += 1;
        Ok(())
    }

    pub(crate) fn handle(&mut self, buf: &mut [u8]) -> QuicResult<()> {
        debug!("handle packet:");
        debug!("     buf = {}", hex::encode(&buf));
        let pdecode = PartialDecode::new(buf)?;
        self.handle_partial(pdecode)
    }

    pub(crate) fn handle_partial(&mut self, partial: PartialDecode) -> QuicResult<()> {
        let PartialDecode {
            header,
            header_len,
            buf,
        } = partial;

        let payload = match header {
            Header::Long { number, .. } | Header::Short { number, .. } => {
                let (header_buf, payload_buf) = buf.split_at_mut(header_len);

                let number = number as u64;
                let number = match header {
                    Header::Short { ptype, .. } =>
                        reconstruct_packet_number(self.dst_pn + 1, number, ptype),
                    _ => number,
                };

                let key_phase = match header {
                    Header::Short{ key_phase, .. } => key_phase,
                    _                              => false
                };

                debug!("     number = {}", number);
                debug!("      state = {:?}", &self.state);
                debug!("     header = {:?}", header);
                debug!("  key_phase = {}", key_phase);

                let decrypted = self.protector.decrypt(
                    number,
                    &header_buf,
                    payload_buf,
                    key_phase
                )?;

                self.dst_pn = number;

                // implicit confirmation

                match self.state {
                    State::ConfirmHandshake => {
                        debug!("  connection confirmed");
                        self.state = State::Connected;
                        self.crypto_offset = 0;
                    }
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

        debug!("handle packet");

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

        let mut prologue = false;
        let mut send_ack = false;
        for frame in &payload {
            debug!("decoded frame:");
            debug!("  {:?}", frame);
            debug!("  {:?}", header.ptype());
            match frame {
                Frame::Crypto(f) => {
                    match header.ptype() {
                        Some(LongType::Initial) =>
                            {
                                if self.side == Side::Client {
                                    self.handle_handshake_message(&f.payload)?;
                                } else if prologue {
                                    self.handle_handshake_message(&f.payload)?;
                                } else {
                                    debug!("  set prologue");
                                    self.handshake.set_prologue(&f.payload)?;
                                    prologue = true;
                                };
                            },
                        Some(LongType::Handshake) => {
                            if self.side == Side::Server {
                                return Err(QuicError::General(format!(
                                     "client received initial message"
                                 )));
                            };
                            self.handle_handshake_message(&f.payload)?
                        },
                        _ => {
                            if self.is_handshaking() {
                                debug!("error, received non-handshake crypto frame during handshake");
                            } else {
                                debug!("received future secrecy message {:?}", &f.payload);
                                self.protector.put_crypto_frame(&f.payload);
                                if self.protector_msg == None {
                                    self.protector.evolve();
                                }
                            }
                        },
                    };
                }
                Frame::Stream(f) => {
                    assert!(!prologue);
                    assert!(self.state == State::Connected);
                    send_ack = true;
                    self.streams.received(f)?;
                }
                Frame::PathChallenge(PathFrame(token)) => {
                    assert!(!prologue);
                    send_ack = true;
                    self.control
                        .push_back(Frame::PathResponse(PathFrame(*token)));
                }
                Frame::ApplicationClose(CloseFrame { code, reason }) => {
                    assert!(!prologue);
                    return Err(QuicError::ApplicationClose(*code, reason.clone()));
                }
                Frame::ConnectionClose(CloseFrame { code, reason }) => {
                    assert!(!prologue);
                    return Err(QuicError::ConnectionClose(*code, reason.clone()));
                }
                Frame::PathResponse(_) | Frame::Ping | Frame::StreamIdBlocked(_) => {
                    assert!(!prologue);
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

        debug!("handle handshake message:");
        debug!("  length = {}", msg.len());
        debug!("     msg = {}", hex::encode(msg));

        let (new_msg, new_secret) = self.handshake.process_message(msg)?;

        // process new key material

        if let Some(secret) = new_secret {

            /* TODO
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

            self.set_rtt1_key(secret);

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
            debug!("send handshake message");
            debug!("  msg = {} ", hex::encode(&msg));
            let length = msg.len() as u64;
            self.control.push_back(Frame::Crypto(CryptoFrame {
                offset  : self.crypto_offset,
                length  : length,
                payload : msg,
            }));
            self.crypto_offset += length;
        }

        Ok(())
    }
}

impl ConnectionState<handshake::ClientSession> {
    pub(crate) fn initial(&mut self, prologue : &[u8]) -> QuicResult<()> {
        debug!("create initial handshake packet");

        let msg = self.handshake.create_handshake_request(prologue)?;

        // push prologue frame

        {
            let length = prologue.len() as u64;
            self.control.push_back(Frame::Crypto(CryptoFrame{
                offset  : self.crypto_offset,
                length  : length,
                payload : prologue.to_owned(),
            }));
            self.crypto_offset += length;
        }

        // push crypto frame

        {
            let length = prologue.len() as u64;
            debug_assert!(length < (1 << 16));
            self.control.push_back(Frame::Crypto(CryptoFrame{
                offset  : self.crypto_offset,
                length  : msg.len() as u64,
                payload : msg,
            }));
            self.crypto_offset += length;
        }

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
