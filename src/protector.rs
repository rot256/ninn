use std::io::Cursor;
use bytes::{Buf, BufMut};

use types::{Side, ConnectionId};
use super::{QuicResult, QuicError};

use hex;
use std::fmt;
use std::fmt::{Debug};

use ring::hkdf;
use ring::aead::{self, OpeningKey, SealingKey};
use ring::aead::AES_256_GCM;
use ring::digest::SHA256;
use ring::hmac::SigningKey;

fn qhkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(2 + 1 + 5 + label.len());
    info.put_u16_be(out.len() as u16);
    info.put_u8(5 + (label.len() as u8));
    info.extend_from_slice(b"quic ");
    info.extend_from_slice(&label);
    assert_eq!(info.len(), 2 + 1 + 5 + label.len());
    hkdf::expand(key, &info, out);
}

/* expands a secret to a Key/IV pair
 */
fn expand_secret(secret: [u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut iv = [0u8; 12];
    let mut key = [0u8; 32];
    let prk = SigningKey::new(&SHA256, &secret);
    qhkdf_expand(&prk, b"iv", &mut iv);
    qhkdf_expand(&prk, b"key", &mut key);
    (key, iv)
}

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
    pub client : [u8; 32],
    pub server : [u8; 32],
}

#[derive(Clone, Copy)]
struct ProtectorKey {
    iv  : [u8; 12],
    key : [u8; 32]
}

impl Debug for ProtectorKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KEY({})", hex::encode(&self.key[..]))
    }
}

impl ProtectorKey {

    fn form_nonce(
        &self,
        pn:  u64,
        out: &mut [u8]
    ) {
        // pad packet number

        debug_assert_eq!(out.len(), AES_256_GCM.nonce_len());
        let out = {
            let mut write = Cursor::new(out);
            write.put_u32_be(0);
            write.put_u64_be(pn);
            debug_assert_eq!(write.remaining(), 0);
            write.into_inner()
        };

        // add IV

        for i in 0..AES_256_GCM.nonce_len() {
            out[i] ^= self.iv[i];
        }
    }

    pub fn new(secret : [u8; 32]) -> ProtectorKey {
        let (key, iv) = expand_secret(secret);
        ProtectorKey{key, iv}
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

        // from nonce from packet number

        let mut nonce = [0u8; 12];
        self.form_nonce(number, &mut nonce);

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

        // from nonce from packet number

        let mut nonce = [0u8; 12];
        self.form_nonce(number, &mut nonce);

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
    side     : Side,                 // endpoint side
    send     : ProtectorKey,         // current sending key
    recv     : ProtectorKey,         // current receiving key
    recv_old : Option<ProtectorKey>, // old receiving key
}

impl Protector1RTT {
    pub fn new(
        secret : Secret,
        side   : Side
    ) -> Protector1RTT {
        let (send, recv) = match side {
            Side::Client => (secret.client, secret.server),
            Side::Server => (secret.server, secret.client),
        };
        Protector1RTT {
            side     : side,
            phase    : false,
            send     : ProtectorKey::new(send),
            recv     : ProtectorKey::new(recv),
            recv_old : None,
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
            return Ok(pt)
        };
        match self.recv_old {
            Some(key) => key.decrypt(number, ad, input),
            None      => Err(QuicError::DecryptError),
        }
    }

    fn evolve(&mut self) {}

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
        None
    }

    fn put_crypto_frame(&mut self, _msg : &[u8]) {}
}

// Handshake obfuscation

#[derive(Debug)]
pub struct ProtectorHandshake {
    send : ProtectorKey,
    recv : ProtectorKey,
}

impl ProtectorHandshake {


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

        let (send, recv) = {
            let prk = ProtectorHandshake::handshake_secret(cid);
            let mut sc = [0u8; 32];
            let mut ss = [0u8; 32];
            qhkdf_expand(&prk, b"client in", &mut sc);
            qhkdf_expand(&prk, b"server in", &mut ss);
            debug!("handshake secrets:");
            debug!("  client = {}", hex::encode(&sc));
            debug!("  server = {}", hex::encode(&ss));
            match side {
                Side::Client => (sc, ss),
                Side::Server => (ss, sc),
            }
        };

        // convert key-material to AEAD keys

        ProtectorHandshake {
            send : ProtectorKey::new(send),
            recv : ProtectorKey::new(recv),
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
        self.send.encrypt(
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
        self.recv.decrypt(number, ad, input)
    }

    fn evolve(&mut self) {}

    fn get_crypto_frame(&mut self) -> Option<Vec<u8>> { None }

    fn put_crypto_frame(&mut self, _msg : &[u8]) {}
}

/*
 * Connection ID: 0xffffffffffffffff
 * client secret: [215 199 37 121 195 238 213 52 251 77 191 28 227 139 18 91 77 83 192 140 122 179 34 122 45 31 197 161 78 15 178 21]
 * server secret: [216 176 221 240 82 202 85 133 153 30 177 240 160 242 46 134 143 63 223 90 15 163 13 158 167 4 211 252 43 215 155 62]
 * client key: [131 172 180 238 131 183 172 219 183 99 105 88 234 69 33 247 89 174 199 214 118 7 7 119 135 60 177 82 118 84 215 180]
 * client iv: [119 118 127 215 87 170 230 134 133 75 77 40]
 * server key: [53 141 115 1 45 183 89 28 7 20 213 22 244 86 188 12 122 201 191 249 242 60 228 139 191 49 67 79 16 15 94 191]
 * server iv: [117 207 41 158 183 244 189 190 95 118 6 7]
 *
 * Connection ID: 0xfafafafafafafafa
 * client secret: [224 24 71 1 18 165 114 179 15 46 18 231 195 109 229 126 250 9 25 206 114 31 73 222 180 147 217 237 47 145 248 137]
 * server secret: [92 85 51 76 20 219 33 237 213 182 113 45 98 24 161 229 110 73 36 149 138 179 134 165 104 198 108 154 197 69 111 67]
 * client key: [65 219 128 235 252 76 94 129 51 88 106 247 104 54 176 106 63 11 242 73 29 95 110 129 235 116 136 2 142 134 128 229]
 * client iv: [200 24 118 69 150 183 203 243 28 80 171 105]
 * server key: [161 98 14 221 245 58 90 127 111 112 140 109 186 213 242 52 68 235 111 165 170 80 38 231 198 156 5 103 136 140 250 37]
 * server iv: [115 208 49 155 133 3 228 219 106 218 182 17]
 *
 * Connection ID: 0xaaaaaaaaaaaaaaaa
 * client secret: [11 21 140 185 55 116 94 138 30 28 5 102 179 125 216 53 5 140 13 159 40 57 202 15 87 150 19 27 49 28 46 48]
 * server secret: [151 133 254 87 78 217 91 43 44 172 114 70 201 138 116 58 12 141 129 40 87 246 68 22 203 14 121 240 44 12 141 72]
 * client key: [81 53 123 121 157 116 178 240 109 47 134 31 102 73 193 220 250 14 222 199 221 159 25 224 228 122 119 153 179 49 16 188]
 * client iv: [173 188 68 19 186 180 17 110 31 32 253 130]
 * server key: [187 10 126 140 151 200 239 235 85 130 121 151 182 104 138 205 84 39 129 159 213 181 116 31 88 228 178 59 111 53 191 106]
 * server iv: [169 150 38 118 4 177 209 130 239 213 255 36]
 *
 * Connection ID: 0xccdbe23ee3be5ab7541d68893c24
 * client secret: [48 88 156 13 177 154 91 195 34 252 146 230 246 58 5 29 28 22 77 85 96 103 147 94 254 6 81 31 130 182 165 119]
 * server secret: [195 194 29 40 109 87 117 10 24 102 207 89 202 134 143 138 175 22 122 82 207 238 43 63 196 3 95 217 232 109 16 30]
 * client key: [20 137 239 53 236 180 174 240 112 234 93 30 19 251 27 38 106 254 37 187 34 202 59 247 204 231 164 104 205 130 162 42]
 * client iv: [162 185 19 166 119 88 197 69 19 193 102 147]
 * server key: [17 143 137 55 152 235 166 228 157 255 228 14 43 72 89 26 2 143 84 57 236 98 211 131 38 187 148 144 129 36 2 172]
 */

#[cfg(test)]
mod tests {
    use hex;
    use codec::Codec;
    use std::io::Cursor;
    use types::{Side, ConnectionId};
    use packet::{ShortType, reconstruct_packet_number};
    use protector::{Protector, ProtectorHandshake};

    struct TestVector {
        cid        : Vec<u8>,
        client_key : [u8; 32],
        client_iv  : [u8; 12],
        server_key : [u8; 32],
        server_iv  : [u8; 12]
    }

    #[test]
    fn test_protector_handshake_vectors() {
        let vectors = vec![
            TestVector {
                cid: vec![
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                client_key: [
                    0xd5, 0xb3, 0x2f, 0x7c, 0x5f, 0xf9, 0x38, 0xa7,
                    0x9a, 0x97, 0x5b, 0x2f, 0x5c, 0x50, 0x50, 0x55,
                    0xaf, 0x12, 0xf1, 0xe6, 0x92, 0xa9, 0x33, 0x6b,
                    0xcf, 0x64, 0x19, 0x3f, 0x3f, 0xae, 0x2f, 0xb7
                ],
                client_iv: [
                    0x86, 0x1f, 0x47, 0xc7, 0x51, 0x4a, 0x37, 0x46,
                    0xee, 0x65, 0xa4, 0x8e
                ],
                server_key: [
                    0xc1, 0x31, 0xc0, 0x41, 0x06, 0x41, 0x1c, 0x71,
                    0x64, 0x9e, 0x98, 0x0e, 0xe1, 0xca, 0xef, 0xc7,
                    0x75, 0x65, 0xb7, 0x77, 0x5e, 0x53, 0x41, 0x5d,
                    0xe3, 0x51, 0x29, 0xda, 0xe4, 0xa2, 0xae, 0x43
                ],
                server_iv: [
                    0xf6, 0x67, 0xe3, 0x27, 0x8e, 0xd7, 0x63, 0xe8,
                    0x3e, 0x25, 0x08, 0xbe
                ]
            },
            TestVector {
                cid: vec![
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                ],
                client_key: [
                    0x83, 0xac, 0xb4, 0xee, 0x83, 0xb7, 0xac, 0xdb,
                    0xb7, 0x63, 0x69, 0x58, 0xea, 0x45, 0x21, 0xf7,
                    0x59, 0xae, 0xc7, 0xd6, 0x76, 0x07, 0x07, 0x77,
                    0x87, 0x3c, 0xb1, 0x52, 0x76, 0x54, 0xd7, 0xb4
                ],
                client_iv: [
                    0x77, 0x76, 0x7f, 0xd7, 0x57, 0xaa, 0xe6, 0x86,
                    0x85, 0x4b, 0x4d, 0x28
                ],
                server_key:  [
                    0x35, 0x8d, 0x73, 0x01, 0x2d, 0xb7, 0x59, 0x1c,
                    0x07, 0x14, 0xd5, 0x16, 0xf4, 0x56, 0xbc, 0x0c,
                    0x7a, 0xc9, 0xbf, 0xf9, 0xf2, 0x3c, 0xe4, 0x8b,
                    0xbf, 0x31, 0x43, 0x4f, 0x10, 0x0f, 0x5e, 0xbf
                ],
                server_iv: [
                    0x75, 0xcf, 0x29, 0x9e, 0xb7, 0xf4, 0xbd, 0xbe,
                    0x5f, 0x76, 0x06, 0x07
                ]
            }
        ];

        for v in vectors {
            let cid = ConnectionId::new(&v.cid);
            let protector = ProtectorHandshake::new(cid, Side::Client);
            assert_eq!(
                hex::encode(&v.client_key),
                hex::encode(&protector.send.key)
            );
            assert_eq!(
                hex::encode(&v.client_iv),
                hex::encode(&protector.send.iv)
            );
            assert_eq!(
                hex::encode(&v.server_key),
                hex::encode(&protector.recv.key)
            );
            assert_eq!(
                hex::encode(&v.server_iv),
                hex::encode(&protector.recv.iv)
            );
        }
    }

    #[test]
    fn test_protector_handshake_roundtrip() {
        let cid = vec![
            0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x65,
        ];
        let nonce = 0xdeadbeef;
        let cid = ConnectionId::new(&cid);
        let protector_client = ProtectorHandshake::new(cid, Side::Client);
        let mut protector_server = ProtectorHandshake::new(cid, Side::Server);

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
            &mut in_out,
            false
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
