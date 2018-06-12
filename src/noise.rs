use ring::digest;
use ring::hmac;
use ring::hkdf;
use ring::aead;

use ring::aead::CHACHA20_POLY1305;
use ring::digest::SHA256;

use super::{QuicError, QuicResult};

pub type SecretKey         = [u8; 32];
pub type PublicKey         = [u8; 32];
pub type HandshakeHash     = [u8; 32];
pub type ChainingKey       = [u8; 32];
pub type AuthenticationTag = [u8; 16];

pub struct Config {
    e  : SecretKey, // local ephemeral secret
    s  : SecretKey, // local static secret
    re : PublicKey, // remote ephemeral public
    rs : PublicKey, // remote static public
}

#[derive(Debug, Copy, Clone)]
pub struct State {
    hs   : HandshakeHash,       // handshake hash
    ck   : ChainingKey,         // chaining key
    temp : Option<ChainingKey>, // encryption key
}

pub fn new_state() -> State {
    // TODO
    State {
        hs   : [0; 32],
        ck   : [0; 32],
        temp : None,
    }
}

fn hkdf(ck: &ChainingKey, material: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let salt = hmac::SigningKey::new(&SHA256, ck); let mut out  = [0; 32*3];
    let mut out1 = [0; 32];
    let mut out2 = [0; 32];
    let mut out3 = [0; 32];
    hkdf::extract_and_expand(&salt, material, &vec![], &mut out);
    out1.copy_from_slice(&out[..32]);
    out2.copy_from_slice(&out[32..64]);
    out3.copy_from_slice(&out[64..]);
    (out1, out2, out3)
}

impl State {
    pub fn mix_hash(&mut self, material: &[u8]) {
        let mut ctx = digest::Context::new(&SHA256);
        ctx.update(&self.hs);
        ctx.update(material);
        self.hs.copy_from_slice(ctx.finish().as_ref());
    }

    pub fn mix_key(&mut self, material: &[u8; 32]) {
        let (ck, temp, _) = hkdf(&self.ck, material);
        self.ck   = ck;
        self.temp = Some(temp);
    }

    fn mix_tag_and_ct(&mut self, tag: &[u8], ct: &[u8]) {
        let mut buf = Vec::new();
        buf.extend(tag);
        buf.extend(ct);
        self.mix_hash(&buf);
    }

    pub fn encrypt_and_hash(&mut self, pt: &[u8]) -> (Vec<u8>, AuthenticationTag) {
        let nonce   = [0; 12];
        let temp    = self.temp.unwrap();
        let aead    = aead::SealingKey::new(&CHACHA20_POLY1305, &temp).unwrap();
        let mut buf = vec![0; CHACHA20_POLY1305.tag_len() + pt.len()];

        aead::seal_in_place(
            &aead,
            &nonce,
            &self.hs,
            &mut buf,
            CHACHA20_POLY1305.tag_len()
        ).unwrap();

        let mut tag = [0; 16];
        let ct      = buf[..pt.len()].to_vec();
        tag.copy_from_slice(&buf[pt.len()..]);

        println!("debug : encrypted, tag = {:?}, ct = {:?}", tag, ct);

        self.mix_tag_and_ct(&tag, &ct);

        (ct, tag)
    }

    pub fn decrypt_and_hash(&mut self, ct: &[u8], tag: &AuthenticationTag) -> QuicResult<Vec<u8>> {
        let nonce  = [0; 12];
        let temp   = self.temp.unwrap();
        let aead   = aead::OpeningKey::new(&CHACHA20_POLY1305, &temp).unwrap();
        let mut pt = vec![0; ct.len()];

        println!("debug : decrypting, tag = {:?}, ct = {:?}", tag, ct);

        pt.copy_from_slice(ct);
        pt.extend(tag.iter());

        match aead::open_in_place(&aead, &nonce, &self.hs, 0, &mut pt) {
            Ok(n)  => Ok(n),
            Err(_) => Err(QuicError::General("failed to authenticat".to_owned())),
        }?;

        self.mix_tag_and_ct(tag, &ct);
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use noise;

    #[test]
    fn test_hkdf() {

        /* Tests generated using flynn/noise */

        fn decode256(v : &str) -> [u8; 32] {
            let mut arr = [0; 32];
            let bytes   = hex::decode(v).unwrap();
            assert_eq!(bytes.len(), 32);
            arr.copy_from_slice(&bytes);
            arr
        }

        let vectors = [
            (("c5968636d622340946b99d35202db9c82383f732d99423e2095b4de224244cb9",
              "2d33c4510cbe6895875c7da8345de88f0b348147ed1d96f7267f6744ad088a17"),
             ("7dc5bc4197ebc1668dd5e03439827867ba1a667201f1d657629386b59a43cd09",
              "02a48646f5ee5960f0a2a1e58352b2c5ab5adb3f29769847f0d55de58cbfbe8f",
              "cb39876304085300bc8bf707888846da8b99a674e0bbba5c13c7b6f42352400c")),

            (("ddddf7ff30cf0d7fdd7d09f94c67778fdd2e3121f8843e59d3f75ce36cf75775",
              "8490483e7e1213b29602370c6ca99d95ff6c499fc8dad8ccac082ad391b4818d"),
             ("e0f1b5126ce11ca8f5c604b75381cdc9bbd3e793066dbacc4187fe626ed6d596",
              "61886f615515f6e3ab3d3145d4708592023c10a5e706e8d72930d9831ee1a15d",
              "8676c9b5037b937449c550329bbfaf02069a33f1c2d6a1fa5d19ed1ee47ade07")),

            (("0000000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000"),
             ("df7204546f1bee78b85324a7898ca119b387e01386d1aef037781d4a8a036aee",
              "a7b65a6e7f873068dd147c56493e71294acc89e73baae2e4a87075f18739b4cd",
              "f0743cc51d27f9b81c0481d34c1e9d42410bda49d6d389387589a364b790742e"))
        ];

        for vec in vectors.iter() {
            let (input, output) = vec;
            let (ck, material)  = input;
            let (v1, v2, v3)    = output;
            let (k1, k2, k3)    = noise::hkdf(
                &decode256(ck),
                &decode256(material)
            );
            assert_eq!(&hex::encode(k1), v1);
            assert_eq!(&hex::encode(k2), v2);
            assert_eq!(&hex::encode(k3), v3);
        }
    }
}
