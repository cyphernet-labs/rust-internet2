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

//! Framed TCP protocol: reads & writes frames (corresponding to LNP messages)
//! from TCP stream

use std::net::TcpStream;

use amplify::Bipolar;
use inet2_addr::InetSocketAddr;

use super::{Duplex, Error, RecvFrame, SendFrame};
use crate::transport::generic::{self, TcpInetStream};

/// Type alias for FTCP connection which is [`generic::Connection`] with FTCP
/// [`Stream`].
pub type Connection = generic::Connection<Stream>;

/// Wrapper type around TCP stream for implementing FTCP-specific traits
#[derive(Debug, From)]
pub struct Stream(TcpStream);

impl Connection {
    pub fn connect(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect_inet_socket(inet_addr)?;
        Ok(Connection::with(stream, inet_addr))
    }

    pub fn accept(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::accept_inet_socket(inet_addr)?;
        Ok(Connection::with(stream, inet_addr))
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
    #[inline]
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> { self.0.recv_frame() }

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
