use std::io::Cursor;
use bytes::{Buf, BufMut};

use types::{Side, ConnectionId};
use super::{QuicResult, QuicError};

use hex;
use dhfuture;
use std::fmt;
use std::fmt::{Debug};

use ring::hkdf;
use ring::aead::{self, OpeningKey, SealingKey};
use ring::aead::AES_256_GCM;
use ring::digest::SHA256;
use ring::hmac::SigningKey;

/* nQUIC evolving packet protector
 */
pub trait Protector : Debug {
    fn encrypt(&self, u64, &[u8], &mut [u8], usize) -> QuicResult<usize>;
    fn decrypt<'a>(&mut self, u64, &[u8], &'a mut [u8], bool) -> QuicResult<&'a mut [u8]>;
    fn evolve(&mut self);
    fn key_phase(&self) -> bool;
    fn get_crypto_frame(&mut self) -> Option<Vec<u8>>;
    fn put_crypto_frame(&mut self, msg : &[u8]);
}

#[derive(Debug)]
pub struct Secret {
    pub hs : [u8; 32],
    pub ck : [u8; 32],
}

fn expand_nonce(nonce: u64, out: &mut [u8]) {
    debug_assert_eq!(out.len(), AES_256_GCM.nonce_len());
    let mut write = Cursor::new(out);
    write.put_u32_be(0);
    write.put_u64_be(nonce);
    debug_assert_eq!(write.remaining(), 0);
}

#[derive(Clone, Copy)]
struct ProtectorKey { key : [u8; 32] }

impl Debug for ProtectorKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KEY({})", hex::encode(&self.key[..]))
    }
}

impl ProtectorKey {

    pub fn new(secret : [u8; 32]) -> ProtectorKey {
        ProtectorKey{
            key   : secret
        }
    }

    pub fn encrypt(
        &self,
        number : u64,
        ad     : &[u8],
        in_out : &mut [u8],
        out_suffix_capacity : usize,
    ) -> QuicResult<usize> {

        // prepare AEAD key

        let key = SealingKey::new(
            &AES_256_GCM, &self.key[..],
        ).map_err(|_| QuicError::EncryptError)?;

        let mut nonce = [0u8; 12];
        expand_nonce(number, &mut nonce);

        // encrypt and auth

        aead::seal_in_place(
            &key,
            &nonce,
            ad,
            in_out,
            out_suffix_capacity
        ).map_err(|_| QuicError::EncryptError)
    }

    pub fn decrypt<'a>(
        &self,
        number    : u64,
        ad        : &[u8],
        input     : &'a mut [u8]
    ) -> QuicResult<&'a mut [u8]> {

        // prepare AEAD key

        let key = OpeningKey::new(
            &AES_256_GCM, &self.key[..],
        ).map_err(|_| QuicError::DecryptError)?;

        // deobfuscate and expand nonce

        let mut nonce = [0u8; 12];
        expand_nonce(number, &mut nonce);

        // decrypt and auth

        aead::open_in_place(
            &key,
            &nonce,
            ad,
            0,
            input,
        ).map_err(|_| QuicError::DecryptError)
    }
}

#[derive(Debug)]
pub struct Protector1RTT {
    phase    : bool,                 // current key phase
    state    : [u8; 32],             // chain state
    side     : Side,                 // endpoint side
    send     : ProtectorKey,         // current sending key
    recv     : ProtectorKey,         // current receiving key
    recv_old : Option<ProtectorKey>, // old receiving key
    dh       : dhfuture::Machine,    // diffie-dellman state machine
}

fn chain(state : &[u8; 32], ikm : &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {

    // HKDF(salt=state, ikm=ikm, info="nquic-ratchet")

    let salt = SigningKey::new(&SHA256, &state[..]);
    let prk  = hkdf::extract(&salt, &ikm[..]);
    let info = "nquic-ratchet".as_bytes();
    let mut out = vec![0u8; 3 * SHA256.output_len];
    hkdf::expand(&prk, &info, &mut out);

    // split

    let mut state = [0u8; 32];
    let mut recv  = [0u8; 32];
    let mut send  = [0u8; 32];

    state.clone_from_slice(&out[..32]);
    recv.clone_from_slice(&out[32..64]);
    send.clone_from_slice(&out[64..]);

    (state, recv, send)
}

fn chain_side(
    side  : Side,
    state : &[u8; 32],
    ikm   : &[u8; 32]
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (state, recv, send) = chain(state, ikm);
    match side {
        Side::Client => (state, recv, send),
        Side::Server => (state, send, recv),
    }
}

impl Protector1RTT {
    pub fn new(
        secret : Secret,
        side   : Side
    ) -> Protector1RTT {
        let (state, recv, send) = chain_side(side, &secret.hs, &secret.ck);
        Protector1RTT {
            side     : side,
            phase    : false,
            state    : state,
            send     : ProtectorKey::new(send),
            recv     : ProtectorKey::new(recv),
            recv_old : None,
            dh       : dhfuture::Machine::new(),
        }
    }
}

impl Protector for Protector1RTT {
    fn decrypt<'a>(
        &mut self,
        number    : u64,          // packet number / nonce
        ad        : &[u8],        // associated data (packet header)
        input     : &'a mut [u8],
        key_phase : bool
    ) -> QuicResult<&'a mut [u8]> {
        if key_phase == self.phase {
            let pt = self.recv.decrypt(number, ad, input)?;
            self.dh.confirmed();
            return Ok(pt)
        };
        match self.recv_old {
            Some(key) => key.decrypt(number, ad, input),
            None      => Err(QuicError::DecryptError),
        }
    }

    fn evolve(&mut self) {
        match self.dh.extract() {
            Some(material) => {

                let (state, recv, send) = chain_side(self.side, &self.state, &material);

                self.recv_old = Some(self.recv);
                self.recv     = ProtectorKey::new(recv);
                self.send     = ProtectorKey::new(send);
                self.state    = state;
                self.phase    = !self.phase;
            },
            None => {},
        }
    }

    fn key_phase(&self) -> bool { self.phase }

    fn encrypt(
        &self,
        number : u64,
        ad     : &[u8],
        in_out : &mut [u8],
        out_suffix_capacity : usize,
    ) -> QuicResult<usize> {
        self.send.encrypt(
            number,
            ad,
            in_out,
            out_suffix_capacity
        )
    }

    fn get_crypto_frame(&mut self) -> Option<Vec<u8>> {
        self.dh.trigger()
    }

    fn put_crypto_frame(&mut self, msg : &[u8]) {
        self.dh.process(msg)
    }
}

// Handshake obfuscation

#[derive(Debug)]
pub struct ProtectorHandshake {
    key_send : ProtectorKey,
    key_recv : ProtectorKey,
}

impl ProtectorHandshake {

    fn expanded_handshake_secret(conn_id: ConnectionId, label: &[u8]) -> Vec<u8> {
        let prk = ProtectorHandshake::handshake_secret(conn_id);
        let mut out = vec![0u8; SHA256.output_len];
        ProtectorHandshake::qhkdf_expand(&prk, label, &mut out);
        out
    }

    fn qhkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
        let mut info = Vec::with_capacity(2 + 1 + 5 + out.len());
        info.put_u16_be(out.len() as u16);
        info.put_u8(5 + (label.len() as u8));
        info.extend_from_slice(b"QUIC ");
        info.extend_from_slice(&label);
        hkdf::expand(key, &info, out);
    }

    fn handshake_secret(conn_id: ConnectionId) -> SigningKey {
        const HANDSHAKE_SALT: &[u8; 20] =
            b"\x9c\x10\x8f\x98\x52\x0a\x5c\x5c\x32\x96\x8e\x95\x0e\x8a\x2c\x5f\xe0\x6d\x6c\x38";
        let key = SigningKey::new(&SHA256, HANDSHAKE_SALT);
        let mut buf = Vec::with_capacity(8);
        buf.put_slice(&conn_id);
        hkdf::extract(&key, &buf)
    }

    pub fn new(cid : ConnectionId, side : Side) -> ProtectorHandshake {

        // derieve keys based on connection id

        let (secret_send, secret_recv) = {
            let sc = ProtectorHandshake::expanded_handshake_secret(cid, b"client hs");
            let ss = ProtectorHandshake::expanded_handshake_secret(cid, b"server hs");
            match side {
                Side::Client => (sc, ss),
                Side::Server => (ss, sc),
            }
        };

        // convert key-material to AEAD keys

        {
            let mut ss = [0u8; 32];
            let mut sr = [0u8; 32];

            ss[..].clone_from_slice(&secret_send);
            sr[..].clone_from_slice(&secret_recv);

            ProtectorHandshake {
                key_send : ProtectorKey::new(ss),
                key_recv : ProtectorKey::new(sr),
            }
        }
    }
}

impl Protector for ProtectorHandshake {
    fn encrypt(
        &self,
        number : u64,
        ad     : &[u8],
        in_out : &mut [u8],
        out_suffix_capacity : usize,
    ) -> QuicResult<usize> {
        self.key_send.encrypt(
            number,
            ad,
            in_out,
            out_suffix_capacity
        )
    }

    fn key_phase(&self) -> bool { false }

    fn decrypt<'a>(
        &mut self,
        number     : u64,
        ad         : &[u8],
        input      : &'a mut [u8],
        _key_phase : bool
    ) -> QuicResult<&'a mut [u8]> {
        self.key_recv.decrypt(number, ad, input)
    }

    fn evolve(&mut self) {}

    fn get_crypto_frame(&mut self) -> Option<Vec<u8>> { None }

    fn put_crypto_frame(&mut self, _msg : &[u8]) {}
}

#[cfg(test)]
mod tests {
    use hex;
    use codec::Codec;
    use std::io::Cursor;
    use types::{Side, ConnectionId};
    use packet::{ShortType, reconstruct_packet_number};
    use protector::{Protector, ProtectorHandshake};

    #[test]
    fn test_protector_handshake() {
        let cid = vec![
            0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x65,
        ];
        let nonce = 0xdeadbeef;
        let cid = ConnectionId::new(&cid);
        let protector_client = ProtectorHandshake::new(cid, Side::Client);
        let protector_server = ProtectorHandshake::new(cid, Side::Server);

        let ad = vec![
            0x79, 0x2e, 0x56, 0xf1,
            0x01, 0x0a, 0x1c, 0xd0,
            0x4d, 0x0b, 0x25, 0xb1,
            0xed, 0x42, 0x4d, 0xaa,
            0x40, 0x85, 0x67, 0xe5,
            0x0a, 0x28, 0x6c, 0xb4,
            0xbe, 0xc5, 0x15, 0x21,
            0x87, 0x01, 0x1c, 0x07,
            0xdd, 0x07, 0xdc, 0xd7,
            0xa7, 0x63, 0xa3, 0x09,
            0xd9, 0xc9, 0xdf, 0x27,
            0xd1, 0x2e, 0xb8, 0xab,
            0x1a, 0xcf, 0x63, 0xec,
            0x21, 0xed, 0x32, 0x67,
            0x03, 0x4a, 0xfc, 0x95,
            0x9c, 0x8b, 0x25, 0x9a
        ];

        let pt = vec![
            0x5b, 0x21, 0x0f, 0x3b,
            0x0d, 0xb3, 0x19, 0xce,
            0xbb, 0x0a, 0xd3, 0x65,
            0xc8, 0xc2, 0x48, 0x7e,
            0x60, 0x5c, 0xf7, 0xdd,
            0x9c, 0xd0, 0x23, 0x94,
            0xb1, 0x12, 0x9a, 0x37,
            0x6b, 0x56, 0xe3, 0xaa,
            0xa6, 0x02, 0x09, 0x29,
            0x7c, 0x86, 0x2a, 0x93,
            0x0e, 0x66, 0x4b, 0x97,
            0xf9, 0xa0, 0xa9, 0xad,
            0x97, 0xc8, 0x89, 0xb8,
            0x55, 0x63, 0x2f, 0xdb,
            0x86, 0xa4, 0xb5, 0x05,
            0xae, 0xf0, 0x70, 0x60,

            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut in_out = pt.clone();

        let len = match protector_client.encrypt(
            nonce,
            &ad,
            &mut in_out,
            16
        ) {
            Err(err) => {
                println!("{:?}", err);
                panic!(err);
            },
            Ok(n) => n,
        };

        let out = match protector_server.decrypt(
            nonce,
            &ad,
            &mut in_out
        ) {
            Err(err) => {
                println!("{:?}", err);
                panic!(err);
            },
            Ok(n) => n,
        };

        assert_eq!(out, &pt[..64])
    }
}
