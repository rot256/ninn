use futures::{task, Async, Future, Poll};

use super::{QuicError, QuicResult};
use conn_state::ConnectionState;
use parameters::ClientTransportParameters;
use streams::Streams;
use handshake;

use std::time::Duration;
use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;
use tokio::prelude::future::Select;

use tokio_core::reactor;

pub struct Client {
    conn_state: ConnectionState<handshake::ClientSession>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn connect(server: &str, port: u16, server_static: [u8; 32], client_static: Option<[u8; 32]>) -> QuicResult<ConnectFuture> {
        ConnectFuture::new(Self::new(server, port, server_static, client_static)?)
    }

    pub(crate) fn new(server: &str, port: u16, server_static: [u8; 32], client_static: Option<[u8; 32]>) -> QuicResult<Client> {
        let handshake = handshake::client_session(
            server_static,
            client_static,
            ClientTransportParameters::default().clone());
        Self::with_state(server, port, ConnectionState::new(handshake, None))
    }

    pub(crate) fn with_state(
        server: &str,
        port: u16,
        conn_state: ConnectionState<handshake::ClientSession>,
    ) -> QuicResult<Client> {
        let addr = (server, port).to_socket_addrs()?.next().ok_or_else(|| {
            QuicError::General(format!("no address found for '{}:{}'", server, port))
        })?;

        let local = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
        };

        let socket = UdpSocket::bind(&local)?;
        socket.connect(&addr)?;
        Ok(Self {
            conn_state,
            socket,
            buf: vec![0u8; 65536],
        })
    }

    fn poll_send(&mut self) -> Poll<(), QuicError> {
        if let Some(buf) = self.conn_state.queued()? {
            let len = try_ready!(self.socket.poll_send(&buf));
            debug_assert_eq!(len, buf.len());
        }
        self.conn_state.pop_queue();
        Ok(Async::Ready(()))
    }
}

impl Future for Client {
    type Item = ();
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.conn_state.streams.set_task(task::current());
        loop {
            match self.poll_send() {
                Ok(Async::Ready(())) | Ok(Async::NotReady) => {}
                e @ Err(_) => try_ready!(e),
            }
            let len = try_ready!(self.socket.poll_recv(&mut self.buf));
            match self.conn_state.handle(&mut self.buf[..len]) {
                Ok(_)  => (),
                Err(err) => {
                    debug!("error, failed to handle message {:?}", err);
                    ()
                }
            }
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    client  : Option<Client>,
    timeout : reactor::Timeout,
}

impl ConnectFuture {
    fn new(mut client: Client) -> QuicResult<ConnectFuture> {
        let core   = reactor::Core::new().unwrap();
        let handle = core.handle();
        Ok(ConnectFuture {
            client: Some(client),
            timeout: reactor::Timeout::new(
                Duration::from_millis(5000), &handle
            ).unwrap()
        })
    }
}

impl Future for ConnectFuture {
    type Item = (Client, Streams);
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        // poll timeout

        match self.timeout.poll() {
            Err(_) => return Err(QuicError::Timeout),
            Ok(Async::Ready(_)) => return Err(QuicError::Timeout),
            _ => (),
        };

        // poll for connection progression

        let done = if let Some(ref mut client) = self.client {
            match client.poll() {
                Err(e) => {
                    return Err(e);
                }
                _ => !client.conn_state.is_handshaking(),
            }
        } else {
            panic!("invalid state for ConnectFuture");
        };

        if done {
            match self.client.take() {
                Some(client) => {
                    let streams = client.conn_state.streams.clone();
                    Ok(Async::Ready((client, streams)))
                }
                _ => panic!("invalid future state"),
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}
