use codec::Codec;
use crypto::Secret;
use parameters::{ClientTransportParameters, ServerTransportParameters};
use types::Side;
use super::{QuicResult};

use nquic::{HandshakeRequest};

use rand::OsRng;

use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;

use ring::aead::AES_128_GCM;
use ring::digest::SHA256;
use ring::digest;
use ring::hmac;
use ring::hkdf;

pub type SecretKey   = [u8; 32];
pub type PublicKey   = [u8; 32];
pub type ChainingKey = [u8; 32];

const STATIC_DUMMY_SECRET : [u8; 32] = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
];

pub struct ClientSession {
    e  : SecretKey, // ephemeral secret
    s  : SecretKey, // static secret
    hs : [u8; 32],  // handshake hash
    ck : [u8; 32],  // chaining key

    params : ClientTransportParameters,
}

pub struct ServerSession {
    e  : SecretKey, // ephemeral
    s  : SecretKey, // static secret
    hs : [u8; 32],  // handshake hash
    ck : [u8; 32],  // chaining key

    params : ServerTransportParameters,
}

pub trait Session {
    fn process_handshake_message(&mut self, &[u8]) -> QuicResult<HandshakeResult>;
}

pub fn client_session(
    remote: PublicKey,
    identity: Option<SecretKey>,
    params: ClientTransportParameters,
) -> ClientSession {
    let mut csprng = OsRng::new().unwrap();
    ClientSession{
        e  : generate_secret(&mut csprng),
        s  : identity.unwrap_or(STATIC_DUMMY_SECRET),
        hs : [0; 32],
        ck : [0; 32],
        params,
    }
}

pub fn server_session(
    identity: SecretKey,
    params: ServerTransportParameters,
) -> ServerSession {
    let mut csprng = OsRng::new().unwrap();
    ServerSession{
        e  : generate_secret(&mut csprng),
        s  : identity,
        hs : [0; 32],
        ck : [0; 32],
        params,
    }
}


impl Session for ClientSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        debug!("process handshake message");


        let k1 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let k2 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let message = vec![];
        let secret  = Secret::For1Rtt(&AES_128_GCM, &SHA256, k1, k2);

        Ok((Some(message), Some(secret)))
    }
}

fn hkdf(ck: &[u8; 32], material: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let salt = hmac::new(&SHA256, ck);
    let mut out  = [0; 32*3];
    let mut out1 = [0; 32];
    let mut out2 = [0; 32];
    let mut out3 = [0; 32];
    hkdf::extract_and_expand(salt, material, vec![], &mut out);
    out1.copy_from_slice(out[..32]);
    out2.copy_from_slice(out[32..64]);
    out3.copy_from_slice(out[64..]);
    out1, out2, out3
}

fn mix_hash(hs: &[u8; 32], v: &[u8]) -> [u8; 32] {
    let mut new_hs = [0; 32];
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(hs);
    ctx.update(v);
    new_hs.copy_from_slice(ctx.finish().as_ref());
    new_hs
}

fn mix_key(hs: &[u8; 32], ck: &[u8; 32], v: &[u8; 32]) {

    salt: &SigningKey,
    secret: &[u8],
    info: &[u8],
    out: &mut [u8]
) -> [u8; 32],  {

    let

}

impl ClientSession {
    pub fn create_handshake_request(&mut self) -> Vec<u8> {

        // noise : e

        let eph = generate_public(&self.e);
        let eph = eph.to_bytes();
        let hs  = mix_hash(&self.hs, &eph);

        // noise : se



        vec![]
    }
}

impl Session for ServerSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        debug!("process handshake message");


        let k1 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let k2 = vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

        let secret  = Secret::For1Rtt(&AES_128_GCM, &SHA256, k1, k2);

        Ok((None, Some(secret)))
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
