extern crate bytes;
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate hex;
extern crate rand;
extern crate ring;
extern crate snow;
extern crate rustls;
extern crate tokio;
extern crate webpki;
extern crate webpki_roots;
extern crate x25519_dalek;
extern crate tokio_core;

pub use client::Client;
pub use server::Server;

mod client;
mod codec;
mod conn_state;
mod frame;
mod nquic;
pub mod http;
mod packet;
mod parameters;
mod server;
mod protector;
pub mod streams;
pub mod handshake;
mod types;

pub trait ClientAuthenticator: Send + Clone {
    fn auth(&self, Option<&[u8; 32]>) -> bool;
}

#[derive(Debug, Fail)]
pub enum QuicError {
    #[fail(display = "{}", _0)]
    AddrParse(#[cause] std::net::AddrParseError),
    #[fail(display = "needed slice of size {}, found {}", _0, _1)]
    AllocationError(usize, usize),
    #[fail(display = "application close ({}): '{}'", _0, _1)]
    ApplicationClose(u16, String),
    #[fail(display = "connection close ({}): '{}'", _0, _1)]
    ConnectionClose(u16, String),
    #[fail(display = "")]
    DecryptError,
    #[fail(display = "")]
    EncryptError,
    #[fail(display = "{}", _0)]
    General(String),
    #[fail(display = "{}", _0)]
    InvalidDnsName(String),
    #[fail(display = "{}", _0)]
    Io(#[cause] std::io::Error),
    #[fail(display = "{}", _0)]
    Tls(#[cause] rustls::TLSError),
    #[fail(display = "{}", _0)]
    DecodeError(String),
    #[fail(display = "")]
    Timeout,
}

impl From<std::io::Error> for QuicError {
    fn from(e: std::io::Error) -> QuicError {
        QuicError::Io(e)
    }
}

impl From<std::net::AddrParseError> for QuicError {
    fn from(e: std::net::AddrParseError) -> QuicError {
        QuicError::AddrParse(e)
    }
}

impl From<rustls::TLSError> for QuicError {
    fn from(e: rustls::TLSError) -> QuicError {
        QuicError::Tls(e)
    }
}

pub type QuicResult<O> = std::result::Result<O, QuicError>;

pub const QUIC_VERSION: u32 = 0xff00_000b;
