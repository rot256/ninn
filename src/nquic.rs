use bytes::{Buf, BufMut};

use codec::{BufLen, Codec, VarLen};

use std::str;

use super::{QuicError, QuicResult};

use handshake::{PublicKey, ClientSession};

const HANDSHAKE_REQUEST_FIXED_LEN : usize = 32 + 16 + 32 + 16;
const HANDSHAKE_RESPONSE_FIXED_LEN : usize = 32 + 16;

pub struct HandshakeRequest {
    ephemeral   : [u8; 32], // initiator ephemeral
    static_tag  : [u8; 16], // initiator identity auth. tag
    static_ct   : [u8; 32], // initiator identity/public static (encrypted)
    payload_tag : [u8; 16], // client transport parameters auth. tag
    payload_ct  : Vec<u8>,  // client transport parameters (encrypted)
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
            static_ct   : [0; 32],
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

pub struct HandshakeResponse {
    ephemeral   : [u8; 32], // responder ephemeral
    payload_tag : [u8; 16], // server transport parameters auth. tag
    payload     : Vec<u8>,  // server transport parameters (encrypted)
}

impl BufLen for HandshakeResponse {
    fn buf_len(&self) -> usize {
        HANDSHAKE_RESPONSE_FIXED_LEN + self.payload.len()
    }
}
