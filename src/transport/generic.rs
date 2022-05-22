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

//! Types generic over specific implementations

use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use amplify::Bipolar;
use inet2_addr::InetSocketAddr;

use crate::transport::{Error, RecvFrame, SendFrame};
use crate::Duplex;

/// A market trait for concrete stream implementations which can be used as a
/// generic parameter in a [`Connection`] object.
pub trait Stream: RecvFrame + SendFrame + From<TcpStream> {}

/// Connection with a stream that can be cloned if split into receiver and
/// sender. Connection combines such stream for a specific destination address.
///
/// This connection type is used by FTCP and Brontide protocols.
#[derive(Debug)]
pub struct Connection<S: Stream> {
    pub(self) stream: S,
    pub(self) remote_addr: InetSocketAddr,
}

impl<S: Stream> Connection<S> {
    pub fn with(stream: TcpStream, remote_addr: InetSocketAddr) -> Self {
        Self {
            stream: S::from(stream),
            remote_addr,
        }
    }
}

impl<S: Stream + Duplex> Duplex for Connection<S> {
    #[inline]
    fn as_receiver(&mut self) -> &mut dyn RecvFrame {
        self.stream.as_receiver()
    }

    #[inline]
    fn as_sender(&mut self) -> &mut dyn SendFrame { self.stream.as_sender() }

    #[inline]
    fn split(self) -> (Box<dyn RecvFrame + Send>, Box<dyn SendFrame + Send>) {
        self.stream.split()
    }
}

impl<S: Stream + Bipolar<Left = S, Right = S>> Bipolar for Connection<S> {
    type Left = S;
    type Right = S;

    fn join(left: S, right: S) -> Self {
        Connection {
            stream: S::join(left, right),
            // TODO: (v1) Replace with remote address
            remote_addr: Default::default(),
        }
    }

    fn split(self) -> (Self::Left, Self::Right) { self.stream.split() }
}

/// Extensions trait for simplifying [`TcpStream`] API in working with
/// [`InetSocketAddr`] sockets
pub trait TcpInetStream: Sized {
    fn connect_inet_socket(inet_addr: InetSocketAddr) -> Result<Self, Error>;

    fn accept_inet_socket(
        listener: &TcpListener,
    ) -> Result<(Self, SocketAddr), Error>;

    fn join(left: Self, right: Self) -> Self;

    fn split(self) -> (Self, Self);
}

impl TcpInetStream for TcpStream {
    fn connect_inet_socket(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        if let Ok(socket_addr) = SocketAddr::try_from(inet_addr) {
            let stream = TcpStream::connect(socket_addr)?;
            // NB: This is how we handle ping-pong cycles
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            Ok(stream)
        } else {
            Err(Error::TorNotSupportedYet)
        }
    }

    fn accept_inet_socket(
        listener: &TcpListener,
    ) -> Result<(Self, SocketAddr), Error> {
        let (stream, remote_addr) = listener.accept()?;
        // NB: This is how we handle ping-pong cycles
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok((stream, remote_addr))
    }

    fn join(left: Self, right: Self) -> Self {
        #[cfg(not(target_os = "windows"))]
        use std::os::unix::io::AsRawFd;
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;

        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            left.as_raw_fd(),
            right.as_raw_fd(),
            "Two independent TCP sockets can't be joined"
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            left.as_raw_socket(),
            right.as_raw_socket(),
            "Two independent TCP sockets can't be joined"
        );

        left
    }

    fn split(self) -> (Self, Self) {
        (self.try_clone().expect("TcpStream cloning failed"), self)
    }
}

impl RecvFrame for TcpStream {
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut len_buf = [0u8; 2];
        self.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf: Vec<u8> = vec![
            0u8;
            len + super::FRAME_PREFIX_SIZE
                + super::FRAME_SUFFIX_SIZE
        ];
        buf[0..2].copy_from_slice(&len_buf);
        self.read_exact(&mut buf[2..])?;
        Ok(buf)
    }

    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl SendFrame for TcpStream {
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE {
            return Err(Error::OversizedFrame(len));
        }
        self.write_all(data)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.write_all(data)?;
        Ok(data.len())
    }
}
