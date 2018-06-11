use crypto::Secret;
use parameters::{ClientTransportParameters, ServerTransportParameters};
use types::Side;
use rand::OsRng;
use bytes::{Buf, BufMut};
use super::{QuicError, QuicResult};
use codec::{BufLen, Codec, VarLen};
use std::io::Cursor;
use std::str;

use noise;

use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;

use ring::aead::AES_128_GCM;
use ring::digest::SHA256;

const STATIC_DUMMY_SECRET : noise::SecretKey = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
];

pub struct ClientSession {
    e      : noise::SecretKey,
    s      : noise::SecretKey,
    rs     : noise::PublicKey,
    st     : noise::State,
    params : ClientTransportParameters,
}

pub struct ServerSession {
    e      : noise::SecretKey,
    s      : noise::SecretKey,
    rs     : noise::PublicKey,
    st     : noise::State,
    params : ServerTransportParameters,
}

const HANDSHAKE_REQUEST_FIXED_LEN  : usize = 32 + 16 + 32 + 16;
const HANDSHAKE_RESPONSE_FIXED_LEN : usize = 32 + 16;

pub struct HandshakeRequest {
    ephemeral   : noise::PublicKey,
    static_tag  : noise::AuthenticationTag,
    static_ct   : Vec<u8>,
    payload_tag : noise::AuthenticationTag,
    payload_ct  : Vec<u8>,
}

pub struct HandshakeResponse {
    ephemeral   : noise::PublicKey,
    payload_tag : noise::AuthenticationTag,
    payload     : Vec<u8>,
}

impl BufLen for HandshakeRequest {
    fn buf_len(&self) -> usize {
        HANDSHAKE_REQUEST_FIXED_LEN + self.payload_ct.len()
    }
}

impl Codec for HandshakeRequest {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_slice(&self.ephemeral);
        buf.put_slice(&self.static_tag);
        buf.put_slice(&self.static_ct);
        buf.put_slice(&self.payload_tag);
        buf.put_slice(&self.payload_ct);
    }

    fn decode<T: Buf>(buf: &mut T) -> QuicResult<Self> {
        let mut msg = HandshakeRequest{
            ephemeral   : [0; 32],
            static_tag  : [0; 16],
            static_ct   : vec![0; 32],
            payload_tag : [0; 16],
            payload_ct  : vec![],
        };

        // read fixed sized fields

        buf.copy_to_slice(&mut msg.ephemeral);
        buf.copy_to_slice(&mut msg.static_tag);
        buf.copy_to_slice(&mut msg.static_ct);
        buf.copy_to_slice(&mut msg.payload_tag);

        // eat variable size field

        msg.payload_ct = vec![0; buf.remaining()];
        buf.copy_to_slice(&mut msg.payload_ct);

        Ok(msg)
    }
}

impl BufLen for HandshakeResponse {
    fn buf_len(&self) -> usize {
        HANDSHAKE_RESPONSE_FIXED_LEN + self.payload.len()
    }
}

pub trait Session {
    fn process_handshake_message(&mut self, &[u8]) -> QuicResult<HandshakeResult>;
}

pub fn client_session(
    remote   : noise::PublicKey,
    identity : Option<noise::SecretKey>,
    params   : ClientTransportParameters,
) -> ClientSession {
    let mut csprng = OsRng::new().unwrap();
    ClientSession{
        e     : generate_secret(&mut csprng),
        s     : identity.unwrap_or(STATIC_DUMMY_SECRET),
        rs    : remote,
        st    : noise::new_state(),
        params,
    }
}

pub fn server_session(
    identity : noise::SecretKey,
    params   : ServerTransportParameters,
) -> ServerSession {
    let mut csprng = OsRng::new().unwrap();
    ServerSession {
        e      : generate_secret(&mut csprng),
        s      : identity,
        rs     : [0; 32],
        st     : noise::new_state(),
        params : params,
    }
}

impl Session for ClientSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        println!("debug : client: process handshake message");

        let k1 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let k2 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let secret  = Secret::For1Rtt(&AES_128_GCM, &SHA256, k1, k2);

        // send transport message

        Ok((None, Some(secret)))
    }
}


impl ClientSession {
    pub fn create_handshake_request(&mut self) -> QuicResult<Vec<u8>> {

        // noise : e

        let eph = generate_public(&self.e);
        let eph = eph.to_bytes();
        self.st.mix_hash(&eph);

        // noise : se

        self.st.mix_key(&diffie_hellman(&self.e, &self.rs));

        println!("debug : noise_state = {:?}", self.st);

        // noise : s

        let spk = generate_public(&self.s);
        let spk = spk.to_bytes();
        let (sct, stag) = self.st.encrypt_and_hash(&spk);

        // noise : ss

        self.st.mix_key(&diffie_hellman(&self.s, &self.rs));

        // encrypt payload

        let mut params = Vec::new();
        self.params.encode(&mut params);
        let (pct, ptag) = self.st.encrypt_and_hash(&params);

        // serialize

        Ok({
            let mut msg = Vec::new();
            HandshakeRequest{
                ephemeral   : eph,
                static_tag  : stag,
                static_ct   : sct,
                payload_tag : ptag,
                payload_ct  : pct,
            }.encode(&mut msg);
            msg
        })
    }
}

impl Session for ServerSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        println!("debug : server : process handshake message");

        // deserialize handshake request

        let mut read = Cursor::new(msg);
        let decoded  = HandshakeRequest::decode(&mut read)?;
        let mut st   = self.st;

        // noise : e

        st.mix_hash(&decoded.ephemeral);

        // noise : se

        st.mix_key(&diffie_hellman(&self.s, &decoded.ephemeral));

        // noise : s

        let rs = st.decrypt_and_hash(&decoded.static_ct, &decoded.static_tag)?;

        println!("debug : client identity = {:?}", rs);

        // noise : ss

        st.mix_key(&diffie_hellman(&self.s, &self.rs));

        Err(QuicError::General("random".to_owned()))
    }
}

pub trait QuicSide {
    fn side(&self) -> Side;
}

impl QuicSide for ClientSession {
    fn side(&self) -> Side {
        Side::Client
    }
}

impl QuicSide for ServerSession {
    fn side(&self) -> Side {
        Side::Server
    }
}

type HandshakeResult = (Option<Vec<u8>>, Option<Secret>);

fn to_vec<T: Codec>(val: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.encode(&mut bytes);
    bytes
}

const ALPN_PROTOCOL: &str = "hq-11";
