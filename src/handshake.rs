use crypto::Secret;
use parameters::{ClientTransportParameters, ServerTransportParameters, TransportParameters};
use types::Side;
use super::{QuicError, QuicResult};
use codec::Codec;
use std::str;
use std::io::Cursor;

use super::QUIC_VERSION;

use hex;

use ring::aead::AES_256_GCM;
use ring::digest::SHA256;

use snow;
use snow::NoiseBuilder;
use snow::params::NoiseParams;

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_IK_25519_AESGCM_SHA256".parse().unwrap();
}

const STATIC_DUMMY_SECRET : [u8; 32] = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
];

const HANDSHAKE_REQUEST_FIXED_LEN  : usize = 32 + 16 + 32 + 16;
const HANDSHAKE_RESPONSE_FIXED_LEN : usize = 32 + 16;

pub struct ClientSession {
    static_key    : [u8; 32],                          // client secret
    remote_key    : [u8; 32],                          // server public
    session       : Option<snow::Session>,             // noise snow session
    params_remote : Option<ServerTransportParameters>, // authenticated remote transport parameters
    params_local  : ClientTransportParameters,         // transport parameters
}

pub struct ServerSession {
    static_key    : [u8; 32],                          // server secret
    session       : Option<snow::Session>,             // noise snow session
    params_remote : Option<ClientTransportParameters>, // authenticated remote transport parameters
    params_local  : ServerTransportParameters,         // transport parameters
    auth_check    : fn([u8; 32]) -> bool               // application specific auth. check
}

pub trait Session {
    fn process_handshake_message(&mut self, &[u8]) -> QuicResult<HandshakeResult>;
    fn set_prologue(&mut self, prologue : &[u8]) -> QuicResult<()>;
    fn get_transport_parameters(&self) -> Option<TransportParameters>;
}

fn no_auth(pk : [u8; 32]) -> bool {
    println!("debug : client identity : {}", hex::encode(&pk));
    true
}

pub fn client_session(
    remote_key : [u8; 32],
    static_key : Option<[u8; 32]>,
    params     : ClientTransportParameters,
) -> ClientSession {
    ClientSession {
        static_key: static_key.unwrap_or(STATIC_DUMMY_SECRET),
        params_remote: None,
        params_local: params,
        remote_key,
        session: None
    }
}

pub fn server_session(
    static_key : [u8; 32],
    params     : ServerTransportParameters,
) -> ServerSession {
    ServerSession {
        static_key: static_key,
        params_remote: None,
        params_local: params,
        session: None,
        auth_check: no_auth,
    }
}

impl Session for ClientSession {
    fn set_prologue(&mut self, _prologue : &[u8]) -> QuicResult<()> {
        Err(QuicError::General("setting prologue on client".to_owned()))
    }

    fn get_transport_parameters(&self) -> Option<TransportParameters> {
        match &self.params_remote {
            Some(p) => Some(p.parameters.clone()),
            None    => None,
        }
    }

    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {
        let session = self.session.as_mut().unwrap();
        let mut payload = vec![0u8; 65535];
        match session.read_message(msg, &mut payload) {
            Ok(n)  => {
                // parse server transport parameters

                self.params_remote = Some({
                    let mut read = Cursor::new(&payload[..n]);
                    ServerTransportParameters::decode(&mut read)?
                });

                assert!(session.is_initiator());
                assert!(session.is_handshake_finished());

                // export key material

                let (k1, k2) = session.export().unwrap();
                let secret   = Secret::For1Rtt(&AES_256_GCM, &SHA256, k1.to_vec(), k2.to_vec());

                println!("debug :   params_remote = {:?}", &self.params_remote);
                println!("debug :   exporting key material from Noise:");
                println!("debug :     i->r : {}", hex::encode(k1));
                println!("debug :     i<-r : {}", hex::encode(k2));

                Ok((None, Some(secret)))
            },
            Err(_) => Err(QuicError::General("failed to decrypt noise".to_owned()))
        }
    }
}

impl ClientSession {
    pub fn create_handshake_request(&mut self, prologue : &[u8]) -> QuicResult<Vec<u8>> {

        // sanity check

        if let Some(_) = self.session {
            panic!("Multiple calls to create_handshake_request");
        }

        // build Noise session

        self.session = Some({
            let builder  = NoiseBuilder::new(PARAMS.clone());
                builder
                    .prologue(prologue)
                    .local_private_key(&self.static_key)
                    .remote_public_key(&self.remote_key)
                    .build_initiator().unwrap()
        });

        // serialize parameters

        let session = self.session.as_mut().unwrap();
        let mut payload = Vec::new();
        self.params_local.encode(&mut payload);

        let mut msg = vec![0u8; 65535];
        let len = session.write_message(&payload, &mut msg).unwrap();

        Ok(msg[..len].to_owned())
    }
}

impl Session for ServerSession {
    fn set_prologue(&mut self, prologue : &[u8]) -> QuicResult<()> {
        match self.session {
            Some(_) =>
                Err(QuicError::General("setting prologue after processing handshake request".to_owned())),
            None => {
                self.session = Some({
                    let builder  = NoiseBuilder::new(PARAMS.clone());
                        builder
                            .local_private_key(&self.static_key)
                            .prologue(prologue)
                            .build_responder().unwrap()
                });
                Ok(())
            }
        }
    }

    fn get_transport_parameters(&self) -> Option<TransportParameters> {
        match &self.params_remote {
            Some(p) => Some(p.parameters.clone()),
            None    => None,
        }
    }

    fn process_handshake_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        println!("debug : process handshake message");

        let session = self.session.as_mut().unwrap();
        let mut payload = vec![0u8; 65535];
        match session.read_message(msg, &mut payload) {
            Ok(n)  => {

                // parse client transport parameters

                let parameters = {
                    let mut read = Cursor::new(&payload[..n]);
                    ClientTransportParameters::decode(&mut read)?
                };
                self.params_remote = Some(parameters.clone());
                println!("debug :   client parameters {:?}", &parameters);

                // validate initial_version (this is the only supported version)

                if parameters.initial_version != QUIC_VERSION {
                    return Err(
                        QuicError::General("failed to decrypt noise".to_owned())
                    );
                };

                // validate client identity

                let auth_ok = match session.get_remote_static() {
                    None      => false,
                    Some(key) => {
                        let mut pk = [0u8; 32];
                        pk[..].clone_from_slice(key);
                        (self.auth_check)(pk)
                    }
                };

                if !auth_ok {
                    return Err(
                        QuicError::General("client idenity rejected".to_owned())
                    );
                }

                // create handshake response

                let resp = {
                    let mut payload = Vec::new();
                    let mut msg = vec![0u8; 65535];
                    self.params_local.encode(&mut payload);
                    let len = session.write_message(&payload, &mut msg).unwrap();
                    assert!(session.is_handshake_finished());
                    msg[..len].to_owned()
                };

                // export transport keys

                println!("debug :   exporting key material from Noise:");

                assert!(!session.is_initiator());
                assert!(session.is_handshake_finished());

                let (k1, k2) = session.export().unwrap();
                let secret   = Secret::For1Rtt(
                    &AES_256_GCM,
                    &SHA256,
                    k1.to_vec(),
                    k2.to_vec()
                );

                println!("debug :     i->r : {}", hex::encode(k1));
                println!("debug :     i<-r : {}", hex::encode(k2));

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
