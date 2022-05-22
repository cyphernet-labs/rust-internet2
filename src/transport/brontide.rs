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

//! Brontide protocol: reads & writes frames (corresponding to LNP messages)
//! from TCP stream according to BOLT-8 requirements.

use std::io::Read;
use std::net::{TcpListener, TcpStream};

use amplify::Bipolar;
use inet2_addr::InetSocketAddr;

use super::{Duplex, Error, RecvFrame, SendFrame};
use crate::session::noise;
use crate::transport::generic::{self, TcpInetStream};

/// Wraps TCP stream for doing framed reads according to BOLT-8 requirements.
#[derive(Debug, From)]
pub struct Stream(TcpStream);

/// Type alias for Brontide connection which is [`generic::Connection`] with
/// Brontide [`Stream`].
pub type Connection = generic::Connection<Stream>;

impl Stream {
    #[inline]
    pub fn with(stream: TcpStream) -> Stream { Stream::from(stream) }
}

impl Connection {
    pub fn connect(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect_inet_socket(inet_addr)?;
        Ok(Connection::with(stream, inet_addr))
    }

    pub fn accept(listener: &TcpListener) -> Result<Self, Error> {
        let (stream, inet_addr) = TcpStream::accept_inet_socket(listener)?;
        Ok(Connection::with(stream, inet_addr.into()))
    }
}

impl generic::Stream for Stream {}

impl Bipolar for Stream {
    type Left = Stream;
    type Right = Stream;

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

impl Duplex for Stream {
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

impl RecvFrame for Stream {
    /// Receive Brontide header. It has a fixed size of 18 bytes and
    /// represents encoded message length.
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> =
            vec![0u8; noise::TAGGED_MESSAGE_LENGTH_HEADER_SIZE];
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

impl SendFrame for Stream {
    #[inline]
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.0.send_frame(data)
    }

    #[inline]
    fn send_raw(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.0.send_raw(data)
    }
}
