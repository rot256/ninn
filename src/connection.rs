use std::sync::{Arc, Mutex};
use std::sync::{Once, ONCE_INIT};

#[derive(Clone)]
pub struct Connection<T> {
    inner : Arc<Mutex<Inner<T>>>
}

struct ServerConnectionContext {
    inner       : Arc<Mutex<Inner<handshake::ServerSession>>>,
    estb_signal : Sender<(Connection<handshake::ServerSession>, Streams)>,
    estb_sent   : bool,
}

struct Inner<T> {
    addr  : SocketAddr,                    // remote address
    state : ConnectionState<T>,            // connection state
    send  : Sender<(SocketAddr, Vec<u8>)>, // outbound datagrams
    recv  : Receiver<Vec<u8>>,             // inbound datagrams
}
