use parameters::{ClientTransportParameters, ServerTransportParameters, TransportParameters};
use types::Side;
use super::{QuicError, QuicResult};
use codec::Codec;
use std::str;
use std::io::Cursor;

use super::{QUIC_VERSION, ClientAuthenticator};

use hex;
use snow;
use protector;

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

const STATIC_DUMMY_PUBLIC : [u8; 32] = [
    0x18, 0x65, 0x6b, 0xa6, 0xd7, 0x86, 0x2c, 0xb1,
    0x1d, 0x99, 0x5a, 0xfe, 0x20, 0xbf, 0x87, 0x61,
    0xed, 0xee, 0x05, 0xec, 0x28, 0xaa, 0x29, 0xbf,
    0xbc, 0xf3, 0x1e, 0xbd, 0x19, 0xde, 0xde, 0x71
];

pub struct ClientSession {
    static_key    : [u8; 32],                          // client secret
    remote_key    : [u8; 32],                          // server public
    session       : Option<snow::Session>,             // noise snow session
    params_remote : Option<ServerTransportParameters>, // authenticated remote transport parameters
    params_local  : ClientTransportParameters,         // transport parameters
}

pub struct ServerSession<A> where A : ClientAuthenticator {
    static_key    : [u8; 32],                          // server secret
    session       : Option<snow::Session>,             // noise snow session
    params_remote : Option<ClientTransportParameters>, // authenticated remote transport parameters
    params_local  : ServerTransportParameters,         // transport parameters
    auth          : Box<A>,                            // application specific auth. check
}

pub trait Session {
    fn process_message(&mut self, &[u8]) -> QuicResult<HandshakeResult>;
    fn set_prologue(&mut self, prologue : &[u8]) -> QuicResult<()>;
    fn get_transport_parameters(&self) -> Option<TransportParameters>;
}

type HandshakeResult = (Option<Vec<u8>>, Option<protector::Secret>);

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

pub fn server_session<A>(
    static_key : [u8; 32],
    params     : ServerTransportParameters,
    auth       : A,
) -> ServerSession<A> where A : ClientAuthenticator {
    ServerSession {
        static_key    : static_key,
        params_remote : None,
        params_local  : params,
        session       : None,
        auth          : Box::new(auth),
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

    fn process_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {
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

                let (hs, ck) = session.export().unwrap();

                debug!("  params_remote = {:?}", &self.params_remote);
                debug!("  exporting key material from Noise:");
                debug!("    hs : {}", hex::encode(hs));
                debug!("    ck : {}", hex::encode(ck));

                Ok((None, Some(protector::Secret{hs, ck})))
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

impl <A> Session for ServerSession<A> where A :ClientAuthenticator {
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

    fn process_message(&mut self, msg: &[u8]) -> QuicResult<HandshakeResult> {

        debug!("process handshake message");

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
                debug!("  client parameters {:?}", &parameters);

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
                        assert_eq!(key.len(), 32);

                        // constant time compare

                        let dummy = key.iter()
                            .zip(STATIC_DUMMY_PUBLIC.iter())
                            .fold(0, |acc, (a, b)| acc | (a ^ b)) == 0;

                        if dummy {
                            self.auth.as_ref().auth(None)
                        } else {
                            let mut pk = [0u8; 32];
                            pk[..].clone_from_slice(key);
                            self.auth.as_ref().auth(Some(&pk))
                        }
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

                debug!("  exporting key material from Noise:");

                assert!(!session.is_initiator());
                assert!(session.is_handshake_finished());

                let (hs, ck) = session.export().unwrap();

                debug!("    hs : {}", hex::encode(hs));
                debug!("    ck : {}", hex::encode(ck));

                Ok((Some(resp), Some(protector::Secret{hs, ck})))
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

impl <A> QuicSide for ServerSession<A> where A : ClientAuthenticator {
    fn side(&self) -> Side {
        Side::Server
    }
}

fn to_vec<T: Codec>(val: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.encode(&mut bytes);
    bytes
}

const ALPN_PROTOCOL: &str = "hq-11";
