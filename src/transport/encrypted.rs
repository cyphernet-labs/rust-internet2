// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020-2021 by
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

//! Noise_XK protocols: reads & writes frames (corresponding to LNP messages)
//! from TCP stream according to Brontide BOLT-8 requirements or LNP/BP
//! Brontozaur protocol.

use std::io::Read;
use std::net::{TcpListener, TcpStream};

use amplify::Bipolar;
use inet2_addr::InetSocketAddr;

use super::{DuplexConnection, Error, RecvFrame, SendFrame};
use crate::session::noise;
use crate::transport::connect::{self, TcpInetStream};

/// Wraps TCP stream for Noise_XK-encrypted data.
#[derive(Debug, From)]
pub struct Stream<const LEN_SIZE: usize>(TcpStream);

/// Type alias for Noise_XK-encrypted connection which is
/// [`connect::Connection`] with TCP [`Stream`].
pub type Connection<const LEN_SIZE: usize> =
    connect::Connection<Stream<LEN_SIZE>>;

impl<const LEN_SIZE: usize> Stream<LEN_SIZE> {
    #[inline]
    pub fn with(stream: TcpStream) -> Stream<LEN_SIZE> { Stream::from(stream) }
}

impl<const LEN_SIZE: usize> Connection<LEN_SIZE> {
    pub fn connect(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect_inet_socket(inet_addr)?;
        Ok(Connection::with(stream, inet_addr))
    }

    pub fn accept(listener: &TcpListener) -> Result<Self, Error> {
        let (stream, inet_addr) = TcpStream::accept_inet_socket(listener)?;
        Ok(Connection::with(stream, inet_addr.into()))
    }
}

impl<const LEN_SIZE: usize> connect::Stream for Stream<LEN_SIZE> {}

impl<const LEN_SIZE: usize> Bipolar for Stream<LEN_SIZE> {
    type Left = Stream<LEN_SIZE>;
    type Right = Stream<LEN_SIZE>;

    #[inline]
    fn join(left: Self::Left, right: Self::Right) -> Self {
        Stream::from(TcpStream::join(left.0, right.0))
    }

    #[inline]
    fn split(self) -> (Self::Left, Self::Right) {
        let (l, r) = self.0.split();
        (Stream::from(l), Stream::from(r))
    }
}

impl<const LEN_SIZE: usize> DuplexConnection for Stream<LEN_SIZE> {
    #[inline]
    fn as_receiver(&mut self) -> &mut dyn RecvFrame { self }

    #[inline]
    fn as_sender(&mut self) -> &mut dyn SendFrame { self }

    #[inline]
    fn split(self) -> (Box<dyn RecvFrame + Send>, Box<dyn SendFrame + Send>) {
        let (r, s) = Bipolar::split(self);
        (Box::new(r), Box::new(s))
    }
}

impl<const LEN_SIZE: usize> RecvFrame for Stream<LEN_SIZE> {
    /// Receive encrypted header. It has a fixed size of 18 or 19 bytes and
    /// represents encoded message length.
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let protocol = noise::FramingProtocol::from(LEN_SIZE);

        let mut buf: Vec<u8> = vec![0u8; protocol.header_size()];
        self.0.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Receive Brontinde encrypted message of variable length. The length is
    /// taken from decoding data returned by [`Stream::recv_frame`].
    #[inline]
    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        self.0.recv_raw(len)
    }
}

impl<const LEN_SIZE: usize> SendFrame for Stream<LEN_SIZE> {
    #[inline]
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.0.send_frame(data)
    }

    #[inline]
    fn send_raw(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.0.send_raw(data)
    }
}
