// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use amplify::{Bipolar, Wrapper};
use inet2_addr::ServiceAddr;

use super::{DuplexConnection, RecvFrame, RoutedFrame, SendFrame};
use crate::transport;

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[repr(u8)]
pub enum ZmqConnectionType {
    #[display("PushPull")]
    PullPush,

    #[display("ReqRep")]
    ReqRep,

    #[display("PubSub")]
    PubSub,

    #[display("Router")]
    Router,
}

impl ZmqConnectionType {
    pub fn socket_in_type(self) -> ZmqSocketType {
        match self {
            ZmqConnectionType::PullPush => ZmqSocketType::Pull,
            ZmqConnectionType::ReqRep => ZmqSocketType::Rep,
            ZmqConnectionType::PubSub => ZmqSocketType::Pub,
            ZmqConnectionType::Router => ZmqSocketType::RouterBind,
        }
    }

    pub fn socket_out_type(self) -> ZmqSocketType {
        match self {
            ZmqConnectionType::PullPush => ZmqSocketType::Push,
            ZmqConnectionType::ReqRep => ZmqSocketType::Req,
            ZmqConnectionType::PubSub => ZmqSocketType::Sub,
            ZmqConnectionType::Router => ZmqSocketType::RouterConnect,
        }
    }
}

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[repr(u8)]
#[non_exhaustive]
pub enum ZmqSocketType {
    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents listening socket ([`zmq::SocketType::PULL`])
    #[display("PULL")]
    Pull = 0,

    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents connected socket ([`zmq::SocketType::PUSH`])
    #[display("PUSH")]
    Push = 1,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents client-side socket ([`zmq::SocketType::REQ`])
    #[display("REQ")]
    Req = 2,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents server-side socket ([`zmq::SocketType::REP`])
    #[display("REP")]
    Rep = 3,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents publisher part ([`zmq::SocketType::PUB`])
    #[display("PUB")]
    Pub = 4,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents subscriber part ([`zmq::SocketType::SUB`])
    #[display("SUB")]
    Sub = 5,

    /// Message bus: each message has a receiver and sender, and multiple peers
    /// may communicate directly with each other in asynchronous mode.
    /// Represents [`zmq::SocketType::ROUTER`] socket which is bind to
    #[display("ROUTER(bind)")]
    RouterBind = 6,

    /// Message bus: each message has a receiver and sender, and multiple peers
    /// may communicate directly with each other in asynchronous mode.
    /// Represents [`zmq::SocketType::ROUTER`] socket wich is connected to
    #[display("ROUTER(connect)")]
    RouterConnect = 7,
}

/// Unknown [`ZmqSocketType`] string
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct UnknownApiType;

impl ZmqSocketType {
    /// Returns [`zmq::SocketType`] corresponding to the given [`ZmqSocketType`]
    pub fn socket_type(&self) -> zmq::SocketType {
        match self {
            ZmqSocketType::Pull => zmq::PULL,
            ZmqSocketType::Push => zmq::PUSH,
            ZmqSocketType::Req => zmq::REQ,
            ZmqSocketType::Rep => zmq::REP,
            ZmqSocketType::Pub => zmq::PUB,
            ZmqSocketType::Sub => zmq::SUB,
            ZmqSocketType::RouterBind => zmq::ROUTER,
            ZmqSocketType::RouterConnect => zmq::ROUTER,
        }
    }

    /// Returns name for the used ZMQ API type that can be used as a part of
    /// URL query
    pub fn api_name(&self) -> String {
        match self {
            ZmqSocketType::Pull | ZmqSocketType::Push => s!("p2p"),
            ZmqSocketType::Req | ZmqSocketType::Rep => s!("rpc"),
            ZmqSocketType::Pub | ZmqSocketType::Sub => s!("sub"),
            ZmqSocketType::RouterBind | ZmqSocketType::RouterConnect => {
                s!("esb")
            }
        }
    }
}

impl FromStr for ZmqSocketType {
    type Err = UnknownApiType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        vec![
            ZmqSocketType::Push,
            ZmqSocketType::Pull,
            ZmqSocketType::Req,
            ZmqSocketType::Rep,
            ZmqSocketType::Pub,
            ZmqSocketType::Sub,
            ZmqSocketType::RouterBind,
            ZmqSocketType::RouterConnect,
        ]
        .into_iter()
        .find(|api| api.to_string() == s)
        .ok_or(UnknownApiType)
    }
}

#[derive(Display)]
pub enum Carrier {
    #[display(inner)]
    Locator(ServiceAddr),

    #[display("zmq_socket(..)")]
    Socket(zmq::Socket),
}

#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Error, From
)]
pub struct Error(i32);

impl From<zmq::Error> for Error {
    #[inline]
    fn from(err: zmq::Error) -> Self { Self(err.to_raw()) }
}

impl From<Error> for zmq::Error {
    #[inline]
    fn from(err: Error) -> Self { zmq::Error::from_raw(err.into_inner()) }
}

impl From<zmq::Error> for transport::Error {
    #[inline]
    fn from(err: zmq::Error) -> Self {
        match err {
            zmq::Error::EHOSTUNREACH => transport::Error::ServiceOffline,
            err => transport::Error::Zmq(err.into()),
        }
    }
}

impl From<Error> for transport::Error {
    #[inline]
    fn from(err: Error) -> Self {
        transport::Error::from(zmq::Error::from(err))
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&zmq::Error::from(*self), f)
    }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&zmq::Error::from(*self), f)
    }
}

pub struct WrappedSocket {
    api_type: ZmqSocketType,
    socket: zmq::Socket,
}

pub struct Connection {
    api_type: ZmqSocketType,
    remote_addr: Option<ServiceAddr>,
    input: WrappedSocket,
    output: Option<WrappedSocket>,
}

impl Connection {
    pub fn with(
        api_type: ZmqSocketType,
        remote: &ServiceAddr,
        local: Option<&ServiceAddr>,
        identity: Option<impl AsRef<[u8]>>,
        context: &zmq::Context,
    ) -> Result<Self, transport::Error> {
        let socket = context.socket(api_type.socket_type())?;
        if let Some(identity) = identity {
            socket.set_identity(identity.as_ref())?;
        }
        let endpoint = remote.zmq_connect_string();
        match api_type {
            ZmqSocketType::Pull
            | ZmqSocketType::Rep
            | ZmqSocketType::Pub
            | ZmqSocketType::RouterBind => socket.bind(&endpoint)?,
            ZmqSocketType::Push
            | ZmqSocketType::Req
            | ZmqSocketType::Sub
            | ZmqSocketType::RouterConnect => socket.connect(&endpoint)?,
        }
        let output = match (api_type, local) {
            (ZmqSocketType::Pull, Some(local)) => {
                let socket = context.socket(zmq::SocketType::PUSH)?;
                socket.connect(&local.zmq_connect_string())?;
                Some(socket)
            }
            (ZmqSocketType::Push, Some(local)) => {
                let socket = context.socket(zmq::SocketType::PULL)?;
                socket.bind(&local.zmq_connect_string())?;
                Some(socket)
            }
            (ZmqSocketType::Pull, None) | (ZmqSocketType::Push, None) => {
                return Err(transport::Error::RequiresLocalSocket)
            }
            (_, _) => None,
        }
        .map(|s| WrappedSocket::from_zmq_socket(api_type, s));
        Ok(Self {
            api_type,
            remote_addr: Some(remote.clone()),
            input: WrappedSocket::from_zmq_socket(api_type, socket),
            output,
        })
    }

    pub fn from_zmq_socket(
        api_type: ZmqSocketType,
        socket: zmq::Socket,
    ) -> Self {
        Self {
            api_type,
            remote_addr: None,
            input: WrappedSocket::from_zmq_socket(api_type, socket),
            output: None,
        }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket { self.input.as_socket() }

    #[inline]
    pub(crate) fn as_socket_mut(&mut self) -> &mut zmq::Socket {
        self.input.as_socket_mut()
    }

    #[inline]
    pub fn set_identity(
        &mut self,
        identity: &impl AsRef<[u8]>,
        context: &zmq::Context,
    ) -> Result<(), Error> {
        let addr = if let Some(addr) = &self.remote_addr {
            addr
        } else {
            return Err(Error::from(zmq::Error::EINVAL));
        };
        let socket = self.input.as_socket_mut();
        let endpoint = addr.zmq_connect_string();
        socket.disconnect(&endpoint)?;
        *socket = context.socket(self.api_type.socket_type())?;
        socket
            .set_identity(identity.as_ref())
            .map_err(Error::from)?;
        match self.api_type {
            ZmqSocketType::Pull
            | ZmqSocketType::Rep
            | ZmqSocketType::Pub
            | ZmqSocketType::RouterBind => socket.bind(&endpoint)?,
            ZmqSocketType::Push
            | ZmqSocketType::Req
            | ZmqSocketType::Sub
            | ZmqSocketType::RouterConnect => socket.connect(&endpoint)?,
        }
        Ok(())
    }
}

impl WrappedSocket {
    #[inline]
    fn from_zmq_socket(api_type: ZmqSocketType, socket: zmq::Socket) -> Self {
        Self { api_type, socket }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket { &self.socket }

    #[inline]
    pub(crate) fn as_socket_mut(&mut self) -> &mut zmq::Socket {
        &mut self.socket
    }
}

impl DuplexConnection for Connection {
    #[inline]
    fn as_receiver(&mut self) -> &mut dyn RecvFrame { &mut self.input }

    #[inline]
    fn as_sender(&mut self) -> &mut dyn SendFrame {
        self.output.as_mut().unwrap_or(&mut self.input)
    }

    fn split(self) -> (Box<dyn RecvFrame + Send>, Box<dyn SendFrame + Send>) {
        if self.api_type == ZmqSocketType::Push
            || self.api_type == ZmqSocketType::Pull
        {
            (
                Box::new(self.input),
                Box::new(self.output.expect(
                    "Splittable types always have output part present",
                )),
            )
        } else {
            // We panic here because this is a program architecture design
            // error and developer must be notified about it; the program using
            // this pattern can't work
            panic!(
                "Split operation is impossible for ZMQ stream type {}",
                self.api_type
            );
        }
    }
}

impl Bipolar for Connection {
    type Left = WrappedSocket;
    type Right = WrappedSocket;

    fn join(input: Self::Left, output: Self::Right) -> Self {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        if input.api_type != output.api_type {
            panic!("ZMQ streams of different type can't be joined");
        }
        if input.api_type != ZmqSocketType::Push
            || input.api_type == ZmqSocketType::Pull
        {
            panic!("ZMQ streams of {} type can't be joined", input.api_type);
        }
        Self {
            api_type: input.api_type,
            remote_addr: None,
            input,
            output: Some(output),
        }
    }

    fn split(self) -> (Self::Left, Self::Right) {
        if self.api_type == ZmqSocketType::Push
            || self.api_type == ZmqSocketType::Pull
        {
            (self.input, self.output.unwrap())
        } else {
            // We panic here because this is a program architecture design
            // error and developer must be notified about it; the program using
            // this pattern can't work
            panic!(
                "Split operation is impossible for ZMQ stream type {}",
                self.api_type
            );
        }
    }
}

impl RecvFrame for WrappedSocket {
    #[inline]
    fn recv_frame(&mut self) -> Result<Vec<u8>, transport::Error> {
        let data = self.socket.recv_bytes(0)?;
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        Ok(data)
    }

    fn recv_raw(&mut self, _len: usize) -> Result<Vec<u8>, transport::Error> {
        // NB: Here we can't guarantee the actual amount of bytes we receive
        Ok(self.socket.recv_bytes(0)?)
    }

    fn recv_routed(&mut self) -> Result<RoutedFrame, transport::Error> {
        let mut multipart = self.socket.recv_multipart(0)?.into_iter();
        // Skipping previous hop data since we do not need them
        let hop = multipart.next().ok_or(transport::Error::FrameBroken(
            "zero frame parts in ZMQ multipart routed frame",
        ))?;
        let src = multipart.next().ok_or(transport::Error::FrameBroken(
            "no source part ZMQ multipart routed frame",
        ))?;
        let dst = multipart.next().ok_or(transport::Error::FrameBroken(
            "no destination part ZMQ multipart routed frame",
        ))?;
        let msg = multipart.next().ok_or(transport::Error::FrameBroken(
            "no message part in ZMQ multipart routed frame",
        ))?;
        if multipart.count() > 0 {
            return Err(transport::Error::FrameBroken(
                "excessive parts in ZMQ multipart routed frame",
            ));
        }
        let len = msg.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        Ok(RoutedFrame { hop, src, dst, msg })
    }
}

impl SendFrame for WrappedSocket {
    #[inline]
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, transport::Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        self.socket.send(data, 0)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<usize, transport::Error> {
        self.socket.send(data, 0)?;
        Ok(data.len())
    }

    fn send_routed(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        data: &[u8],
    ) -> Result<usize, transport::Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        self.socket
            .send_multipart(&[route, source, dest, data], 0)?;
        Ok(data.len())
    }
}
