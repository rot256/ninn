extern crate env_logger;
extern crate ninn;
extern crate tokio;
extern crate futures;
extern crate hex;

use std::time::*;
use futures::prelude::*;
use std::thread;

#[derive(Clone)]
struct Authenticator {}

impl ninn::ClientAuthenticator for Authenticator {
    fn auth(&self, pk : Option<&[u8; 32]>) -> bool {
        println!("auth : {:?}", pk);
        true
    }
}

fn main() {
    let server_sk = [
        0x08, 0x65, 0x45, 0xae,
        0xc9, 0xe6, 0x92, 0x73,
        0x84, 0x69, 0xce, 0xa3,
        0x91, 0x77, 0x45, 0x8d,
        0xbe, 0xaa, 0xde, 0x23,
        0xad, 0x42, 0x55, 0xbc,
        0xf2, 0x28, 0xa9, 0x49,
        0xc7, 0x0f, 0x3c, 0x74
    ];

    env_logger::init();

    let auth = Authenticator{};

    let server = ninn::Server::new("0.0.0.0", 8888, server_sk, auth)
        .unwrap().for_each(
            |strm| {

                // echo server

                tokio::spawn(
                    strm.request_stream(0).map_err(|err| {
                        println!("server: err = {:?}", err);
                    }).map(|mut strm| {
                        println!("server: new stream created");
                        loop {
                            match strm.get_stream(0) {
                                None => {},
                                Some(estrm) => {
                                    let res = match estrm.received() {
                                        Ok(data) => {
                                            estrm.send(&data[..]).unwrap();
                                            let mut m = Vec::with_capacity(1024);
                                            strm.poll_send(&mut m);
                                        }
                                        Err(_)   => {}
                                    };
                                    thread::sleep(
                                        Duration::from_millis(500)
                                    );
                                    res
                                },
                            }
                        }
                    })
                );
                Ok(())
            }
    );
    tokio::run(server);
}
