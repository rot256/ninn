# Ninn

Ninn is a PoC implementation of the Noise-QUIC (nQUIC) draft in Rust, based on the Quinn library.
This implementation is currently somewhere between QUIC-Transport-11 and QUIC-Transport-13,
in particular it implements QUIC-Transport-11 with CRYPTO frames as defined in QUIC-Transport-13.

## nQUIC

nQUIC (Noise + QUIC) is an alternative version of the QUIC transport protocol
using a Noised(IK) based cryptographic handshake in place of TLS1.3 (used in IETF QUIC).
Core features of nQUIC are:

- Easy implementation
- Server authentication
- Optional client authentication
- Forward and future secrecy (using a Signal-Style KDF-ratchet)
- 1-RTT connection establishment (including the cryptographic handshake)
- Small handshake overhead (both processing and bandwidth)
- Simpler formal analysis
- No PKI support

nQUIC is particularly well-suited for applications where both endpoints
are deployed and configured by the same party, e.g.
database connections,
mobile applications,
between data center locations and "IoT".

nQUIC provides significantly better protection in cases where endpoints are compromised
than other transport encryption currently in deployment,
which makes it perfectly suited for long-lived connections
where momentary compromise of cryptographic state should not allow decryption
of previous or even future data sent between the endpoints.

## Usage

A simple example client and server is included in this repository.
The client continually sends data to the server over stream 0 and the server accumulated the stream frames
and periodically returns the clients contents on stream 0.

~~~
$ cargo run --bin server
$ cargo run --bin client -- 127.0.0.1
~~~

Run the programs with `RUST_LOG=debug` to print debug output showing
handshake negotiation details, key material, key rotations, the packet protector status and more. e.g.

~~~
$ RUST_LOG=debug cargo run --bin server
$ RUST_LOG=debug cargo run --bin client -- 127.0.0.1
~~~
