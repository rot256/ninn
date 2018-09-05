use futures::sync::mpsc::{self, Receiver, Sender};
use futures::{task, Async, AsyncSink, Future, Poll, Sink, Stream};

use super::{QuicError, QuicResult, ClientAuthenticator};
use conn_state::ConnectionState;
use packet::{LongType, PartialDecode};
use parameters::ServerTransportParameters;
use handshake;
use types::ConnectionId;
use streams::Streams;

use std::collections::{hash_map::Entry, HashMap};
use std::net::{SocketAddr, ToSocketAddrs};

use tokio::{self, net::UdpSocket};

pub struct Server<A> where A : ClientAuthenticator + 'static {
    socket: UdpSocket,
    in_buf: Vec<u8>,
    connections: HashMap<ConnectionId, Sender<Vec<u8>>>,

    /* Provides multiplexing of UDP datagrams
     * based on connection IDs
     */
    send_queue: PacketChannel,

    /* Provides feedback from connection state
     * of established connections (post handshake)
     */
    established_send: Sender<Streams>,
    established_recv: Receiver<Streams>,
    established_closed: bool,

    key  : [u8; 32],
    auth : Box<A>
}

type PacketChannel = (
    Sender<(SocketAddr, Vec<u8>)>,
    Receiver<(SocketAddr, Vec<u8>)>,
);

impl <A> Server<A> where A : ClientAuthenticator {
    pub fn new(ip: &str, port: u16, key: [u8; 32], auth : A) -> QuicResult<Self> {
        let addr = (ip, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| QuicError::General("no address found for host".into()))?;
        let (send, recv) = mpsc::channel(5);
        Ok(Server {
            auth : Box::new(auth),
            socket: UdpSocket::bind(&addr)?,
            in_buf: vec![0u8; 65536],
            connections: HashMap::new(),
            send_queue: mpsc::channel(5),
            established_send: send,
            established_recv: recv,
            established_closed: false,
            key,
        })
    }

    fn received(&mut self, addr: SocketAddr, len: usize) -> QuicResult<()> {
        let connections = &mut self.connections;
        let packet = &mut self.in_buf[..len];

        let (dst_cid, ptype) = {
            let partial = PartialDecode::new(packet)?;
            debug!("incoming packet: {:?} {:?}", addr, partial.header);
            (partial.dst_cid(), partial.header.ptype())
        };

        let cid = if ptype == Some(LongType::Initial) {
            let mut state = ConnectionState::new(
                handshake::server_session(self.key, ServerTransportParameters::default().clone(), self.auth.as_ref().clone()),
                Some(dst_cid),
            );

            let cid = state.pick_unused_cid(|cid| connections.contains_key(&cid));
            let (recv_tx, recv_rx) = mpsc::channel(5);
            tokio::spawn(
                Connection::new(
                    addr,
                    state,
                    self.send_queue.0.clone(),
                    recv_rx,
                    self.established_send.clone(),
                ).map_err(|e| {
                    error!("error spawning connection: {:?}", e);
                }),
            );
            connections.insert(cid, recv_tx);
            cid
        } else {
            dst_cid
        };

        match connections.entry(cid) {
            Entry::Occupied(mut inner) => {
                let mut sink = inner.get_mut();
                forward_packet(sink, packet.to_vec())?;
            }
            Entry::Vacant(_) => debug!("connection ID {:?} unknown", cid),
        }

        Ok(())
    }

    fn poll_next(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        match self.send_queue.1.poll() {
            Ok(Async::Ready(msg)) => msg,
            Ok(Async::NotReady) => None,
            Err(e) => {
                error!("error polling send queue: {:?}", e);
                None
            }
        }
    }
}

impl <A> Stream for Server<A> where A : ClientAuthenticator {
    type Item = Streams;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

        let mut waiting;
        loop {
            waiting = true;

            // handle inbound datagrams

            match self.socket.poll_recv_from(&mut self.in_buf) {
                Ok(Async::Ready((len, addr))) => {
                    waiting = false;
                    if let Err(e) = self.received(addr, len) {
                        error!("error while handling received packet: {:?}", e);
                    }
                }
                Ok(Async::NotReady) => {}
                Err(e) => error!("Server RECV ERROR: {:?}", e),
            }

            // poll for established connections

            if !self.established_closed {
                match self.established_recv.poll() {
                    Ok(Async::Ready(Some(strm))) => {
                        return Ok(Async::Ready(
                            Some(strm)
                        ));
                    }
                    Ok(Async::Ready(None)) => {
                        return Ok(Async::Ready(None));
                    }
                    Ok(Async::NotReady) => {}
                    Err(e) => error!("Server RECV ERROR: {:?}", e)
                }
            }

            // deliver output datagrams

            if let Some((addr, msg)) = self.poll_next() {
                waiting = false;
                match self.socket.poll_send_to(&msg, &addr) {
                    Ok(Async::Ready(_)) => {}
                    Ok(Async::NotReady) => {}
                    Err(e) => error!("Server poll_send_to ERROR {:?}", e),
                }
            }

            if waiting {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

fn forward_packet(sink: &mut Sender<Vec<u8>>, msg: Vec<u8>) -> QuicResult<()> {
    match sink.start_send(msg) {
        Ok(AsyncSink::Ready) => {}
        Ok(AsyncSink::NotReady(msg)) => error!("discarding message: {:?}", msg),
        Err(e) => {
            return Err(QuicError::General(format!(
                "error while starting channel send: {:?}",
                e
            )));
        }
    }
    match sink.poll_complete() {
        Ok(Async::Ready(())) => {}
        Ok(Async::NotReady) => {}
        Err(e) => {
            return Err(QuicError::General(format!(
                "error while polling channel complete: {:?}",
                e
            )));
        }
    }
    Ok(())
}

struct Connection<A> where A : ClientAuthenticator {
    addr: SocketAddr,
    state: ConnectionState<handshake::ServerSession<A>>,
    send: Sender<(SocketAddr, Vec<u8>)>,
    recv: Receiver<Vec<u8>>,
    conn: Sender<Streams>,
    confirmed: bool,
}

impl <A> Connection<A> where A : ClientAuthenticator {
    fn new(
        addr: SocketAddr,
        state: ConnectionState<handshake::ServerSession<A>>,
        send: Sender<(SocketAddr, Vec<u8>)>,
        recv: Receiver<Vec<u8>>,
        conn: Sender<Streams>,
    ) -> Self {
        Self {
            addr,
            state,
            send,
            recv,
            conn,
            confirmed: false,
        }
    }
}

impl <A> Future for Connection<A> where A : ClientAuthenticator {
    type Item = ();
    type Error = ();
    fn poll(&mut self) -> Poll<(), ()> {
        loop {

            // handle incoming UDP datagrams

            let mut received = false;
            match self.recv.poll() {
                Ok(Async::Ready(Some(ref mut msg))) => {
                    match self.state.handle(msg) {
                        Ok(_) => {
                            received = true;
                        }
                        Err(err) => {
                            debug!("error, failed to handle incoming message {:?}", err);
                        }
                    }
                }
                Ok(Async::Ready(None)) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from server: {:?}", e),
            }

            // handle handshake complete

            if !self.state.is_handshaking() && !self.confirmed {
                match self.conn.poll_ready() {
                    Ok(Async::Ready(_)) => {
                        self.confirmed = true;
                        match self.conn.start_send(self.state.streams.clone()) {
                            Err(e) => error!("error polling {:?}", e),
                            _      => {},
                        }
                    },
                    Err(e) => error!("error polling {:?}", e),
                    _ => ()
                };
            }

            // handle output messages

            let mut sent = false;
            match self.state.queued() {
                Ok(Some(msg)) => match self.send.start_send((self.addr, msg.clone())) {
                    Ok(AsyncSink::Ready) => {
                        sent = true;
                    }
                    Ok(AsyncSink::NotReady(msg)) => {
                        error!("start send not ready: {:?}", msg);
                    }
                    Err(e) => error!("error sending: {:?}", e),
                },
                Ok(None) => {
                    // giant hack. TODO: fix
                    // causes huge CPU util. will fix upstream (Quinn)
                    task::current().notify();
                }
                Err(e)   => error!("error from connection state: {:?}", e),
            }

            if sent {
                self.state.pop_queue();
            }

            // handle closed, flushing

            let flushed = false;
            match self.send.poll_complete() {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from flushing sender: {:?}", e),
            }

            if !(received || sent || flushed) {
                break;
            }
        }

        Ok(Async::NotReady)
    }
}

