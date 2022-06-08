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

use std::any::Any;
#[cfg(feature = "keygen")]
use std::net::TcpListener;

#[cfg(feature = "keygen")]
use addr::NodeAddr;
use amplify::Bipolar;
#[cfg(feature = "keygen")]
use inet2_addr::InetSocketAddr;
#[cfg(feature = "zmq")]
use inet2_addr::ServiceAddr;

use super::{Decrypt, Encrypt, Transcode};
use crate::session::noise::FramingProtocol;
use crate::session::{noise, PlainTranscoder};
use crate::transport::{
    encrypted, unencrypted, DuplexConnection, Error, RecvFrame, RoutedFrame,
    SendFrame,
};
#[cfg(feature = "zmq")]
use crate::zeromq;
use crate::{NoiseDecryptor, NoiseTranscoder};

// Generics prevents us from using session as `&dyn` reference, so we have
// to avoid `where Self: Input + Output` and generic parameters, unlike with
// `Transcode`
pub trait SendRecvMessage {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error>;
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error>;
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error>;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

pub trait Split {
    fn split(
        self,
    ) -> (Box<dyn RecvMessage + Send>, Box<dyn SendMessage + Send>);
}

pub trait RecvMessage {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen transport")
    }
}

pub trait SendMessage {
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error>;
    fn send_routed_message(
        &mut self,
        _source: &[u8],
        _route: &[u8],
        _dest: &[u8],
        _raw: &[u8],
    ) -> Result<usize, Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen transport")
    }
}

pub struct Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: DuplexConnection + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    pub(self) transcoder: T,
    pub(self) connection: C,
}

pub struct Receiver<D, R>
where
    D: Decrypt,
    R: RecvFrame,
{
    pub(self) decryptor: D,
    pub(self) input: R,
}

pub struct Sender<E, S>
where
    E: Encrypt,
    S: SendFrame,
{
    pub(self) encryptor: E,
    pub(self) output: S,
}

// Private trait used to avoid code duplication below
trait InternalSession {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error>;
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error>;
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error>;
}

impl<T, C> InternalSession for Session<T, C>
where
    T: Transcode + 'static,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: DuplexConnection + Bipolar + 'static,
    C::Left: RecvFrame,
    C::Right: SendFrame,
    Error: From<T::Error> + From<<T::Left as Decrypt>::Error>,
{
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.connection.as_receiver();
        Ok(self.transcoder.decrypt(reader.recv_frame()?)?)
    }

    #[inline]
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        let writer = self.connection.as_sender();
        writer.send_frame(&self.transcoder.encrypt(raw))
    }

    #[inline]
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        let reader = self.connection.as_receiver();
        let mut routed_frame = reader.recv_routed()?;
        routed_frame.msg = self.transcoder.decrypt(routed_frame.msg)?;
        Ok(routed_frame)
    }

    #[inline]
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error> {
        let writer = self.connection.as_sender();
        writer.send_routed(source, route, dest, &self.transcoder.encrypt(raw))
    }
}

impl SendRecvMessage for Session<PlainTranscoder, unencrypted::Connection> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalSession::recv_raw_message(self)
    }
    #[inline]
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        InternalSession::send_raw_message(self, raw)
    }
    #[inline]
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalSession::recv_routed_message(self)
    }
    #[inline]
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error> {
        InternalSession::send_routed_message(self, source, route, dest, raw)
    }
    #[inline]
    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

fn recv_brontide_message<const LEN_SIZE: usize>(
    reader: &mut dyn RecvFrame,
    decrypt: &mut NoiseDecryptor<LEN_SIZE>,
) -> Result<Vec<u8>, Error> {
    // Reading & decrypting length
    let encrypted_len = reader.recv_frame()?;
    decrypt.decrypt(encrypted_len)?;
    let len = decrypt.pending_message_len();
    if len == None {
        return Err(Error::NoBrontideHeader);
    }

    let len = len.unwrap_or_default();
    // Reading & decrypting payload
    let encrypted_payload =
        reader.recv_raw(len as usize + noise::chacha::TAG_SIZE)?;
    let payload = decrypt.decrypt(encrypted_payload)?;
    Ok(payload)
}

impl<const LEN_SIZE: usize> SendRecvMessage
    for Session<NoiseTranscoder<LEN_SIZE>, encrypted::Connection>
{
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.connection.as_receiver();
        recv_brontide_message(reader, &mut self.transcoder.decryptor)
    }

    #[inline]
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        InternalSession::send_raw_message(self, raw)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        unimplemented!(
            "to route brontide messages use presentation-level onion routing"
        )
    }
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error> {
        unimplemented!(
            "to route brontide messages use presentation-level onion routing"
        )
    }
    #[inline]
    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

#[cfg(feature = "zmq")]
impl SendRecvMessage for Session<PlainTranscoder, zeromq::Connection> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalSession::recv_raw_message(self)
    }
    #[inline]
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        InternalSession::send_raw_message(self, raw)
    }
    #[inline]
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalSession::recv_routed_message(self)
    }
    #[inline]
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error> {
        InternalSession::send_routed_message(self, source, route, dest, raw)
    }
    #[inline]
    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

impl<T, C> Split for Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt + Send + 'static,
    T::Right: Encrypt + Send + 'static,
    C: DuplexConnection + Bipolar,
    C::Left: RecvFrame + Send + 'static,
    C::Right: SendFrame + Send + 'static,
    Receiver<T::Left, C::Left>: RecvMessage,
    Error: From<T::Error> + From<<T::Left as Decrypt>::Error>,
{
    #[inline]
    fn split(
        self,
    ) -> (Box<dyn RecvMessage + Send>, Box<dyn SendMessage + Send>) {
        let (decryptor, encryptor) = self.transcoder.split();
        let (input, output) = Bipolar::split(self.connection);
        (
            Box::new(Receiver { decryptor, input }),
            Box::new(Sender { encryptor, output }),
        )
    }
}

pub type BrontideSession = Session<
    NoiseTranscoder<{ FramingProtocol::Brontide.message_len_size() }>,
    encrypted::Connection,
>;
pub type BrontozaurSession = Session<
    NoiseTranscoder<{ FramingProtocol::Brontozaur.message_len_size() }>,
    encrypted::Connection,
>;
#[cfg(feature = "zmq")]
pub type LocalSession = Session<PlainTranscoder, zeromq::Connection>;
#[cfg(feature = "zmq")]
pub type RpcSession = Session<
    NoiseTranscoder<{ FramingProtocol::Brontozaur.message_len_size() }>,
    zeromq::Connection,
>;

#[cfg(feature = "keygen")]
impl BrontideSession {
    pub fn with(
        stream: std::net::TcpStream,
        local_key: secp256k1::SecretKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        BrontideSession::with_tcp_encrypted(stream, local_key, remote_addr)
    }

    pub fn connect(
        local_key: secp256k1::SecretKey,
        remote_node: NodeAddr,
    ) -> Result<Self, Error> {
        BrontideSession::connect_tcp_encrypted(local_key, remote_node)
    }

    pub fn accept(
        local_key: secp256k1::SecretKey,
        listener: &TcpListener,
    ) -> Result<Self, Error> {
        BrontideSession::accept_tcp_encrypted(local_key, listener)
    }
}

#[cfg(feature = "keygen")]
impl BrontozaurSession {
    pub fn with(
        stream: std::net::TcpStream,
        local_key: secp256k1::SecretKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        BrontozaurSession::with_tcp_encrypted(stream, local_key, remote_addr)
    }

    pub fn connect(
        local_key: secp256k1::SecretKey,
        remote_node: NodeAddr,
    ) -> Result<Self, Error> {
        BrontozaurSession::connect_tcp_encrypted(local_key, remote_node)
    }

    pub fn accept(
        local_key: secp256k1::SecretKey,
        listener: &TcpListener,
    ) -> Result<Self, Error> {
        BrontozaurSession::accept_tcp_encrypted(local_key, listener)
    }
}

#[cfg(feature = "zmq")]
impl LocalSession {
    pub fn with(
        zmq_type: zeromq::ZmqSocketType,
        remote: &ServiceAddr,
        local: Option<ServiceAddr>,
        identity: Option<&[u8]>,
        context: &zmq::Context,
    ) -> Result<Self, Error> {
        LocalSession::with_zmq_unencrypted(
            zmq_type, remote, local, identity, context,
        )
    }
}

/* TODO: Needs more work due to ZMQ PUSH/PULL sockets using two connections
#[cfg(all(feature = "zmq", feature = "keygen"))]
impl RpcSession {
    pub fn with(
        zmq_type: zeromq::ZmqSocketType,
        remote: &ServiceAddr,
        local: Option<ServiceAddr>,
        identity: Option<&[u8]>,
        context: &zmq::Context,
    ) -> Result<Self, Error> {
        RpcSession::with_zmq_encrypted(
            zmq_type, remote, local, identity, context,
        )
    }

    pub fn from_zmq_socket(
        zmq_type: zeromq::ZmqSocketType,
        socket: zmq::Socket,
    ) -> Self {
        RpcSession::from_zmq_socket_encrypted(zmq_type, socket)
    }
}
 */

#[cfg(feature = "keygen")]
impl<const LEN_SIZE: usize>
    Session<NoiseTranscoder<LEN_SIZE>, encrypted::Connection>
{
    fn with_tcp_encrypted(
        stream: std::net::TcpStream,
        local_key: secp256k1::SecretKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Self::init_tcp_encrypted(
            local_key,
            encrypted::Connection::with(stream, remote_addr),
        )
    }

    fn connect_tcp_encrypted(
        local_key: secp256k1::SecretKey,
        remote_node: NodeAddr,
    ) -> Result<Self, Error> {
        let mut connection = encrypted::Connection::connect(remote_node.addr)?;
        let transcoder = NoiseTranscoder::new_initiator(
            local_key,
            remote_node.public_key(),
            &mut connection,
        )?;
        Ok(Self {
            transcoder,
            connection,
        })
    }

    fn accept_tcp_encrypted(
        local_key: secp256k1::SecretKey,
        listener: &TcpListener,
    ) -> Result<Self, Error> {
        Self::init_tcp_encrypted(
            local_key,
            encrypted::Connection::accept(listener)?,
        )
    }

    fn init_tcp_encrypted(
        local_key: secp256k1::SecretKey,
        mut connection: encrypted::Connection,
    ) -> Result<Self, Error> {
        let transcoder =
            NoiseTranscoder::new_responder(local_key, &mut connection)?;
        Ok(Self {
            transcoder,
            connection,
        })
    }
}

/* TODO: Needs more work due to ZMQ PUSH/PULL sockets using two connections
#[cfg(all(feature = "zmq", feature = "keygen"))]
impl
    Session<
        NoiseTranscoder<{ FramingProtocol::Brontozaur.message_len_size() }>,
        zeromq::Connection,
    >
{
    fn connect_zmq_encrypted(
        zmq_type: ZmqConnectionType,
        remote_node: &NodeAddr,
        local_key: secp256k1::SecretKey,
        local: Option<ServiceAddr>,
        identity: Option<&[u8]>,
        context: &zmq::Context,
    ) -> Result<Self, Error> {
        let mut socket = SocketAddr::try_from(remote_node.addr).map_err(|_| Error::TorNotSupportedYet)?;
        let mut connection = zeromq::Connection::with(
            zmq_type.socket_out_type(), &ServiceAddr::Tcp(socket), local, identity, context,
        )?;
        let transcoder = NoiseTranscoder::new_initiator(local_key, remote_node.public_key(), &mut connection)?;
        Ok(Self {
            transcoder,
            connection
        })
    }

    fn bind_zmq_encrypted(
        zmq_type: ZmqConnectionType,
        bind_addr: &InetSocketAddr,
        local_key: secp256k1::SecretKey,
        identity: Option<&[u8]>,
        context: &zmq::Context,
    ) -> Result<Self, Error> {
        let mut socket = SocketAddr::try_from(remote_node).map_err(|_| Error::TorNotSupportedYet)?;
        let mut connection = zeromq::Connection::with(
            zmq_type.socket_in_type(), &ServiceAddr::Tcp(socket), local, identity, context,
        )?;
        let transcoder = NoiseTranscoder::new_responder(local_key, &mut connection)?;
        Ok(Self {
            transcoder,
            connection
        })
    }
}
 */

#[cfg(feature = "zmq")]
impl Session<PlainTranscoder, zeromq::Connection> {
    fn with_zmq_unencrypted(
        zmq_type: zeromq::ZmqSocketType,
        remote: &ServiceAddr,
        local: Option<ServiceAddr>,
        identity: Option<&[u8]>,
        context: &zmq::Context,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: zeromq::Connection::with(
                zmq_type, remote, local, identity, context,
            )?,
        })
    }

    fn from_zmq_socket_unencrypted(
        zmq_type: zeromq::ZmqSocketType,
        socket: zmq::Socket,
    ) -> Self {
        Self {
            transcoder: PlainTranscoder,
            connection: zeromq::Connection::from_zmq_socket(zmq_type, socket),
        }
    }
}

#[cfg(feature = "zmq")]
impl<T> Session<T, zeromq::Connection>
where
    T: Transcode,
    T::Left: Decrypt + Send + 'static,
    T::Right: Encrypt + Send + 'static,
{
    pub fn as_socket(&self) -> &zmq::Socket { self.connection.as_socket() }

    pub fn set_identity(
        &mut self,
        identity: &impl AsRef<[u8]>,
        context: &zmq::Context,
    ) -> Result<(), Error> {
        self.connection
            .set_identity(identity, context)
            .map_err(Error::from)
    }
}

// Private trait used to avoid code duplication below
trait InternalInput {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error>;
}

impl<T, C> InternalInput for Receiver<T, C>
where
    T: Decrypt,
    C: RecvFrame,
    // TODO: (new) Use session-level error type
    Error: From<T::Error>,
{
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.decryptor.decrypt(self.input.recv_frame()?)?)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        let mut routed_frame = self.input.recv_routed()?;
        routed_frame.msg = self.decryptor.decrypt(routed_frame.msg)?;
        Ok(routed_frame)
    }
}

impl RecvMessage for Receiver<PlainTranscoder, unencrypted::Stream> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalInput::recv_raw_message(self)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalInput::recv_routed_message(self)
    }
}

impl<const LEN_SIZE: usize> RecvMessage
    for Receiver<NoiseDecryptor<LEN_SIZE>, encrypted::Stream>
{
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        recv_brontide_message(&mut self.input, &mut self.decryptor)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalInput::recv_routed_message(self)
    }
}

#[cfg(feature = "zmq")]
impl RecvMessage for Receiver<PlainTranscoder, zeromq::WrappedSocket> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalInput::recv_raw_message(self)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalInput::recv_routed_message(self)
    }
}

impl<T, C> SendMessage for Sender<T, C>
where
    T: Encrypt,
    C: SendFrame,
{
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        self.output.send_frame(&self.encryptor.encrypt(raw))
    }
    fn send_routed_message(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        raw: &[u8],
    ) -> Result<usize, Error> {
        let encrypted = self.encryptor.encrypt(raw);
        self.output.send_routed(source, route, dest, &encrypted)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "zmq")]
    fn test_zmq_no_encryption() {
        let ctx = zmq::Context::new();
        let locator = ServiceAddr::Inproc(s!("test"));
        let mut rx = Session::with_zmq_unencrypted(
            zeromq::ZmqSocketType::Rep,
            &locator,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let mut tx = Session::with_zmq_unencrypted(
            zeromq::ZmqSocketType::Req,
            &locator,
            None,
            None,
            &ctx,
        )
        .unwrap();

        let msg = b"Some message";
        SendRecvMessage::send_raw_message(&mut tx, msg).unwrap();
        assert_eq!(SendRecvMessage::recv_raw_message(&mut rx).unwrap(), msg);

        let msg = b"";
        SendRecvMessage::send_raw_message(&mut rx, msg).unwrap();
        assert_eq!(SendRecvMessage::recv_raw_message(&mut tx).unwrap(), msg);
    }
}
