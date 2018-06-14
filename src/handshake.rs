use crypto::Secret;
use parameters::{ClientTransportParameters, ServerTransportParameters};
use types::Side;
use rand::OsRng;
use bytes::{Buf, BufMut};
use super::{QuicError, QuicResult};
use codec::{BufLen, Codec, VarLen};
use std::io::Cursor;
use std::str;

use hex;

use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;

use ring::aead::AES_256_GCM;
use ring::digest::SHA256;

use snow;
use snow::NoiseBuilder;
use snow::params::NoiseParams;

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256".parse().unwrap();
}

const STATIC_DUMMY_SECRET : [u8; 32] = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
];

pub struct ClientSession {
    session    : snow::Session,
    params     : ClientTransportParameters,
}

pub struct ServerSession {
    session    : snow::Session,
    params     : ServerTransportParameters,
}

const HANDSHAKE_REQUEST_FIXED_LEN  : usize = 32 + 16 + 32 + 16;
const HANDSHAKE_RESPONSE_FIXED_LEN : usize = 32 + 16;

pub trait Session {
    fn process_handshake_message(&mut self, &[u8]) -> QuicResult<HandshakeResult>;
}

pub fn client_session(
    remote_key : [u8; 32],
    static_key : Option<[u8; 32]>,
    params     : ClientTransportParameters,
) -> ClientSession {
    let builder    = NoiseBuilder::new(PARAMS.clone());
    let static_key = static_key.unwrap_or(STATIC_DUMMY_SECRET);
    ClientSession{
        session : builder
            .local_private_key(&static_key)
            .remote_public_key(&remote_key)
            .build_initiator().unwrap(),
        params,
    }
}

pub fn server_session(
    static_key : [u8; 32],
    params     : ServerTransportParameters,
) -> ServerSession {
    let builder = NoiseBuilder::new(PARAMS.clone());
    ServerSession {
        session : builder
            .local_private_key(&static_key)
            .build_responder().unwrap(),
        params,
    }
}

impl Session for ClientSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        // process handshake response

        let mut payload = vec![0u8; 65535];
        match self.session.read_message(msg, &mut payload) {
            Ok(n)  => {
                // TODO: parse server transport parameters

                // export transport keys

                println!("debug : client exporting key material from Noise:");

                assert!(self.session.is_initiator());
                assert!(self.session.is_handshake_finished());

                let (k1, k2) = self.session.export().unwrap();
                let secret   = Secret::For1Rtt(&AES_256_GCM, &SHA256, k1.to_vec(), k2.to_vec());

                println!("debug :   i->r : {}", hex::encode(k1));
                println!("debug :   i<-r : {}", hex::encode(k2));

                Ok((None, Some(secret)))
            },
            Err(_) => Err(QuicError::General("failed to decrypt noise".to_owned()))
        }
    }
}

impl ClientSession {
    pub fn create_handshake_request(&mut self) -> QuicResult<Vec<u8>> {

        let mut payload = Vec::new();
        self.params.encode(&mut payload);

        let mut msg = vec![0u8; 65535];
        let len = self.session.write_message(&payload, &mut msg).unwrap();

        Ok(msg[..len].to_owned())
    }
}

impl Session for ServerSession {
    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        println!("debug : server : process handshake message");

        let mut payload = vec![0u8; 65535];
        match self.session.read_message(msg, &mut payload) {
            Ok(n)  => {

                // TODO: parse client transport parameters

                // TODO: validate initial_version

                // TODO: check client identity (pass to application)

                println!("debug : client identity {:?}", self.session.get_remote_static());

                // create handshake response

                let resp = {
                    let mut payload = Vec::new();
                    let mut msg = vec![0u8; 65535];
                    self.params.encode(&mut payload);
                    let len = self.session.write_message(&payload, &mut msg).unwrap();
                    assert!(self.session.is_handshake_finished());
                    msg[..len].to_owned()
                };

                // export transport keys

                println!("debug : server exporting key material from Noise:");

                assert!(!self.session.is_initiator());
                assert!(self.session.is_handshake_finished());

                let (k1, k2) = self.session.export().unwrap();
                let secret   = Secret::For1Rtt(
                    &AES_256_GCM,
                    &SHA256,
                    k1.to_vec(),
                    k2.to_vec()
                );

                println!("debug :   i->r : {}", hex::encode(k1));
                println!("debug :   i<-r : {}", hex::encode(k2));

                Ok((Some(resp), Some(secret)))
            },
            Err(_) => Err(QuicError::General("failed to decrypt noise".to_owned()))
        }
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
