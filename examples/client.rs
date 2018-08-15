extern crate env_logger;
extern crate futures;
extern crate ninn;
extern crate tokio;
extern crate webpki;

use futures::future::{ok, loop_fn, Future, Loop};

use std::env;
use std::thread;

use futures::*;
use std::time::*;

fn main() {
    let server_pk = [
        0x33, 0x2b, 0x2f, 0x56,
        0xbb, 0x4e, 0x28, 0x4a,
        0x2e, 0x87, 0xe7, 0x69,
        0x0d, 0x51, 0xf1, 0x29,
        0x14, 0xa5, 0x9b, 0x3b,
        0x8e, 0x03, 0x56, 0xd8,
        0x23, 0xe0, 0x32, 0x61,
        0x0a, 0xfd, 0xd6, 0x61
    ];

    env_logger::init();

    assert_eq!(server_pk.len(), 32);

    let server = env::args().nth(1).expect("need server name as an argument");

    println!("Connect to : {}", server);

    let _res : Result<(), _> = ninn::Client::connect(&server, 8888, server_pk, None)
            .unwrap()
            .and_then(|conn| {

                // open stream

                let (client, strm) = conn;
                let stream = match strm.get_stream(0) {
                    Some(s) => s,
                    None => {
                        let stream = strm.init_send(ninn::streams::Dir::Bidi).unwrap();
                        debug_assert_eq!(stream.id, 0);
                        stream
                    }
                };

                loop_fn((client, stream, 0), | (mut client, stream, n) | {

                    // write some stuff to stream 0

                    let test = (0u8..32).collect::<Vec<_>>();
                    stream.send(&test[..]).unwrap();

                    // send as much stream as possible

                    loop {
                        match client.poll().unwrap() {
                            Async::Ready(_) => {},
                            Async::NotReady => {
                                break;
                            },
                        }
                    }

                    thread::sleep(
                        Duration::from_millis(500)
                    );

                    ok(Loop::Continue((client, stream, n + 1)))
                })
            }).wait();
    println!(
        "RESULT: ",
    );
}
