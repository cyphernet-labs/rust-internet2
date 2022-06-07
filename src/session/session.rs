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
use std::net::TcpListener;

use amplify::Bipolar;
use inet2_addr::{InetSocketAddr, ServiceAddr};

use super::{Decrypt, Encrypt, Transcode};
#[cfg(feature = "keygen")]
use crate::session::noise::HandshakeState;
use crate::session::{noise, PlainTranscoder};
use crate::transport::{
    encrypted, unencrypted, Duplex, Error, RecvFrame, RoutedFrame, SendFrame,
};
#[cfg(feature = "zmq")]
use crate::zeromq;
use crate::{NoiseDecryptor, NoiseTranscoder};

// Generics prevents us from using session as `&dyn` reference, so we have
// to avoid `where Self: Input + Output` and generic parameters, unlike with
// `Transcode`
pub trait Session {
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
    fn split(self) -> (Box<dyn Input + Send>, Box<dyn Output + Send>);
}

pub trait Input {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen transport")
    }
}

pub trait Output {
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

pub struct Raw<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Duplex + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    pub(self) transcoder: T,
    pub(self) connection: C,
}

pub struct RawInput<D, R>
where
    D: Decrypt,
    R: RecvFrame,
{
    pub(self) decryptor: D,
    pub(self) input: R,
}

pub struct RawOutput<E, S>
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

impl<T, C> InternalSession for Raw<T, C>
where
    T: Transcode + 'static,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Duplex + Bipolar + 'static,
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

impl Session for Raw<PlainTranscoder, unencrypted::Connection> {
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

impl<const LEN_SIZE: usize> Session
    for Raw<NoiseTranscoder<LEN_SIZE>, encrypted::Connection>
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
impl Session for Raw<PlainTranscoder, zeromq::Connection> {
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

impl<T, C> Split for Raw<T, C>
where
    T: Transcode,
    T::Left: Decrypt + Send + 'static,
    T::Right: Encrypt + Send + 'static,
    C: Duplex + Bipolar,
    C::Left: RecvFrame + Send + 'static,
    C::Right: SendFrame + Send + 'static,
    RawInput<T::Left, C::Left>: Input,
    Error: From<T::Error> + From<<T::Left as Decrypt>::Error>,
{
    #[inline]
    fn split(self) -> (Box<dyn Input + Send>, Box<dyn Output + Send>) {
        let (decryptor, encryptor) = self.transcoder.split();
        let (input, output) = Bipolar::split(self.connection);
        (
            Box::new(RawInput { decryptor, input }),
            Box::new(RawOutput { encryptor, output }),
        )
    }
}

impl Raw<PlainTranscoder, unencrypted::Connection> {
    pub fn with_ftcp(
        stream: std::net::TcpStream,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: unencrypted::Connection::with(stream, remote_addr),
        })
    }

    pub fn connect_ftcp(socket_addr: InetSocketAddr) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: unencrypted::Connection::connect(socket_addr)?,
        })
    }

    pub fn accept_ftcp(listener: &TcpListener) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: unencrypted::Connection::accept(listener)?,
        })
    }
}

#[cfg(feature = "keygen")]
impl<const LEN_SIZE: usize>
    Raw<NoiseTranscoder<LEN_SIZE>, encrypted::Connection>
{
    pub fn with_brontide(
        stream: std::net::TcpStream,
        local_key: secp256k1::SecretKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Self::init_brontide(
            encrypted::Connection::with(stream, remote_addr.into()),
            local_key,
        )
    }

    pub fn connect_brontide(
        local_key: secp256k1::SecretKey,
        remote_key: secp256k1::PublicKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let ephemeral_key = secp256k1::SecretKey::new(&mut rng);
        let mut handshake = HandshakeState::new_initiator(
            &local_key,
            &remote_key,
            &ephemeral_key,
        );

        let mut connection = encrypted::Connection::connect(remote_addr)?;

        let mut data = vec![];
        let transcoder = loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let Some(ref act) = act {
                connection.as_sender().send_raw(&*act)?;
                if let HandshakeState::Complete(Some((transcoder, pk))) =
                    handshake
                {
                    break transcoder;
                }
                data =
                    connection.as_receiver().recv_raw(handshake.data_len())?;
            }
        };

        Ok(Self {
            transcoder,
            connection,
        })
    }

    pub fn accept_brontide(
        local_key: secp256k1::SecretKey,
        listener: &TcpListener,
    ) -> Result<Self, Error> {
        Self::init_brontide(encrypted::Connection::accept(listener)?, local_key)
    }

    fn init_brontide(
        mut connection: encrypted::Connection,
        local_key: secp256k1::SecretKey,
    ) -> Result<Self, Error> {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let ephemeral_key = secp256k1::SecretKey::new(&mut rng);
        let mut handshake =
            HandshakeState::new_responder(&local_key, &ephemeral_key);

        let mut data =
            connection.as_receiver().recv_raw(handshake.data_len())?;
        let transcoder = loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let HandshakeState::Complete(Some((transcoder, pk))) = handshake
            {
                break transcoder;
            }
            if let Some(act) = act {
                connection.as_sender().send_raw(&*act)?;
                data =
                    connection.as_receiver().recv_raw(handshake.data_len())?;
            }
        };

        Ok(Self {
            transcoder,
            connection,
        })
    }
}

#[cfg(feature = "zmq")]
impl Raw<PlainTranscoder, zeromq::Connection> {
    pub fn with_zmq_unencrypted(
        zmq_type: zeromq::ZmqType,
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

    pub fn from_zmq_socket_unencrypted(
        zmq_type: zeromq::ZmqType,
        socket: zmq::Socket,
    ) -> Self {
        Self {
            transcoder: PlainTranscoder,
            connection: zeromq::Connection::from_zmq_socket(zmq_type, socket),
        }
    }
}

#[cfg(feature = "zmq")]
impl<T> Raw<T, zeromq::Connection>
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

impl<T, C> InternalInput for RawInput<T, C>
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

impl Input for RawInput<PlainTranscoder, unencrypted::Stream> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalInput::recv_raw_message(self)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalInput::recv_routed_message(self)
    }
}

impl<const LEN_SIZE: usize> Input
    for RawInput<NoiseDecryptor<LEN_SIZE>, encrypted::Stream>
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
impl Input for RawInput<PlainTranscoder, zeromq::WrappedSocket> {
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        InternalInput::recv_raw_message(self)
    }
    fn recv_routed_message(&mut self) -> Result<RoutedFrame, Error> {
        InternalInput::recv_routed_message(self)
    }
}

impl<T, C> Output for RawOutput<T, C>
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
        let mut rx = Raw::with_zmq_unencrypted(
            zeromq::ZmqType::Rep,
            &locator,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let mut tx = Raw::with_zmq_unencrypted(
            zeromq::ZmqType::Req,
            &locator,
            None,
            None,
            &ctx,
        )
        .unwrap();

        let msg = b"Some message";
        Session::send_raw_message(&mut tx, msg).unwrap();
        assert_eq!(Session::recv_raw_message(&mut rx).unwrap(), msg);

        let msg = b"";
        Session::send_raw_message(&mut rx, msg).unwrap();
        assert_eq!(Session::recv_raw_message(&mut tx).unwrap(), msg);
    }
}
