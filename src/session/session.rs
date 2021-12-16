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

use amplify::Bipolar;
use inet2_addr::InetSocketAddr;

use super::{Decrypt, Encrypt, Transcode};
#[cfg(feature = "keygen")]
use crate::session::noise::HandshakeState;
use crate::session::PlainTranscoder;
use crate::transport::{
    brontide, ftcp, Duplex, Error, RecvFrame, RoutedFrame, SendFrame,
};
#[cfg(feature = "zmq")]
use crate::zmqsocket;
#[cfg(feature = "keygen")]
use crate::NoiseTranscoder;

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

impl Session for Raw<PlainTranscoder, ftcp::Connection> {
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
        InternalSession::send_raw_message(self, raw)
    }
    #[inline]
    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

impl Session for Raw<NoiseTranscoder, brontide::Connection> {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.connection.as_receiver();

        // Reading & decrypting length
        let encrypted_len = reader.recv_frame()?;
        let len_slice = self.transcoder.decrypt(encrypted_len)?;
        if len_slice.len() != 2 {
            return Err(Error::InvalidLength {
                expected: 2,
                actual: len_slice.len() as u16,
            });
        }
        let mut len_bytes = [0u8; 2];
        len_bytes.copy_from_slice(&len_slice);
        let len = u16::from_be_bytes(len_bytes);

        // Reading & decrypting payload
        let encrypted_payload = reader.recv_raw(len as usize)?;
        let payload = self.transcoder.decrypt(encrypted_payload)?;
        Ok(payload)
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
impl Session for Raw<PlainTranscoder, zmqsocket::Connection> {
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
        InternalSession::send_raw_message(self, raw)
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

impl Raw<PlainTranscoder, ftcp::Connection> {
    pub fn with_ftcp_unencrypted(
        stream: std::net::TcpStream,
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: ftcp::Connection::with(stream, socket_addr),
        })
    }

    pub fn connect_ftcp_unencrypted(
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: ftcp::Connection::connect(socket_addr)?,
        })
    }

    pub fn accept_ftcp_unencrypted(
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: ftcp::Connection::accept(socket_addr)?,
        })
    }
}

#[cfg(feature = "keygen")]
impl Raw<NoiseTranscoder, brontide::Connection> {
    pub fn connect_ftcp_encrypted(
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

        let mut connection = brontide::Connection::connect(remote_addr)?;

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

    pub fn accept_ftcp_encrypted(
        local_key: secp256k1::SecretKey,
        remote_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let ephemeral_key = secp256k1::SecretKey::new(&mut rng);
        let mut handshake =
            HandshakeState::new_responder(&local_key, &ephemeral_key);

        let mut connection = brontide::Connection::accept(remote_addr)?;

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
impl Raw<PlainTranscoder, zmqsocket::Connection> {
    pub fn with_zmq_unencrypted(
        zmq_type: zmqsocket::ZmqType,
        remote: &zmqsocket::ZmqSocketAddr,
        local: Option<zmqsocket::ZmqSocketAddr>,
        identity: Option<&[u8]>,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: PlainTranscoder,
            connection: zmqsocket::Connection::with(
                zmq_type, remote, local, identity,
            )?,
        })
    }

    pub fn from_zmq_socket_unencrypted(
        zmq_type: zmqsocket::ZmqType,
        socket: zmq::Socket,
    ) -> Self {
        Self {
            transcoder: PlainTranscoder,
            connection: zmqsocket::Connection::from_zmq_socket(
                zmq_type, socket,
            ),
        }
    }
}

#[cfg(feature = "zmq")]
impl<T> Raw<T, zmqsocket::Connection>
where
    T: Transcode,
    T::Left: Decrypt + Send + 'static,
    T::Right: Encrypt + Send + 'static,
{
    pub fn as_socket(&self) -> &zmq::Socket { self.connection.as_socket() }
}

impl<T, C> Input for RawInput<T, C>
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
        let locator = zmqsocket::ZmqSocketAddr::Inproc(s!("test"));
        let mut rx = Raw::with_zmq_unencrypted(
            zmqsocket::ZmqType::Rep,
            &locator,
            None,
            None,
        )
        .unwrap();
        let mut tx = Raw::with_zmq_unencrypted(
            zmqsocket::ZmqType::Req,
            &locator,
            None,
            None,
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
