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
