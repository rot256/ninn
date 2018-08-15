use std::time::{SystemTime};

use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;
use rand::OsRng;

#[derive(Debug)]
pub struct Machine {
    last      : SystemTime,
    secret    : Option<[u8; 32]>, // local DH secret
    public    : Option<[u8; 32]>, // remote DH public
    confirmed : bool
}

impl Machine {
    pub fn new() -> Machine {
        Machine{
            last      : SystemTime::now(), // key material is fresh
            secret    : None,
            public    : None,
            confirmed : true,
        }
    }

    pub fn extract(&mut self) -> Option<[u8; 32]> {
        match (self.secret, self.public) {
            (Some(sk), Some(pk)) => {
                self.secret    = None;
                self.public    = None;
                self.confirmed = false;
                self.last      = SystemTime::now();
                debug!("computed shared secret {:?}", diffie_hellman(&sk, &pk));
                Some(diffie_hellman(&sk, &pk))
            },
            _ => None
        }
    }

    pub fn trigger(&mut self) -> Option<Vec<u8>> {

        // await confirmation

        if !self.confirmed || self.secret != None {
            return None;
        }

        match self.last.elapsed() {
            Ok(elapsed) => {
                if elapsed.as_secs() < 10 { // Dummy Value, should be something like 60 secs
                    return None;
                };
            },
            Err(_e) => {
                return None;
            }
        }

        // generate diffie-hellman secret

        let mut csprng = OsRng::new().unwrap();
        let sk         = generate_secret(&mut csprng);
        let pk         = generate_public(&sk);
        self.secret    = Some(sk);
        Some(pk.as_bytes()[..].to_owned())
    }

    pub fn process(&mut self, msg : &[u8])  {

        // check valid public key

        if msg.len() != 32 {
            return;
        }

        // save remote public key

        match self.public {
            None => {
                let mut pk = [0u8; 32];
                pk[..].clone_from_slice(msg);
                self.public = Some(pk);
            }
            Some(_) => {
                debug!("the remote state machine is buggy, this should never happen");
            }
        }
    }

    pub fn confirmed(&mut self) {
        self.confirmed = true;
    }
}

