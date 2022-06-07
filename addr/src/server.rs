// Internet2 addresses with support for Tor v3
//
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//     Martin Habovstiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::net::{self, SocketAddr};
use std::str::FromStr;

use crate::node::NodeAddrParseError;
use crate::{AddrParseError, InetSocketAddr, NodeAddr};

/// Errors parsing [`ServerAddr`] string representation
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum ServerAddrParseError {
    /// Invalid node address
    #[from]
    #[display(inner)]
    InvalidNode(NodeAddrParseError),

    /// Invalid internet socket address
    #[from]
    #[display(inner)]
    InvalidAddr(AddrParseError),

    /// invalid server address string '{0}'
    Unrecognized(String),
}

/// Server address representing connection to a remote or a local server over
/// ZMQ protocol.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ServerAddr {
    /// Encrypted connection over TCP
    #[display("{0}", alt = "bronze://{0}")]
    #[from]
    Bronze(NodeAddr),

    /// Unencrypted connection over TCP
    #[display("{0}", alt = "tcp://{0}")]
    #[from]
    Tcp(InetSocketAddr),

    /// Local IPC connection
    #[display("{0}", alt = "ipc://{0}")]
    #[from]
    Ipc(String),
}

impl FromStr for ServerAddr {
    type Err = ServerAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split("://");
        Ok(match (split.next(), split.next(), split.next()) {
            (Some("bronze"), Some(s), None) => NodeAddr::from_str(s)?.into(),
            (Some("tcp"), Some(s), None) => InetSocketAddr::from_str(s)?.into(),
            (Some("ipc"), Some(s), None) => ServerAddr::Ipc(s.to_owned()),
            (Some(s), None, _) => NodeAddr::from_str(s)
                .map(ServerAddr::from)
                .map_err(ServerAddrParseError::from)
                .or_else(|_| {
                    InetSocketAddr::from_str(s)
                        .map(ServerAddr::from)
                        .map_err(ServerAddrParseError::from)
                })
                .unwrap_or_else(|_| ServerAddr::Ipc(s.to_owned())),
            _ => return Err(ServerAddrParseError::Unrecognized(s.to_owned())),
        })
    }
}

/// Errors parsing [`ServiceAddr`] string representation
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ServiceAddrParseError {
    /// Invalid internet socket address
    #[from]
    #[display(inner)]
    InvalidAddr(net::AddrParseError),

    /// invalid server address string '{0}'
    Unrecognized(String),
}

/// Address of microservice which may be local or remote; standalone process or
/// a thread, connectable via ZMQ.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ServiceAddr {
    /// Connection via TCP
    #[display("{0}", alt = "tcp://{0}")]
    #[from]
    Tcp(SocketAddr),

    /// Connection via IPC
    #[display("{0}", alt = "ipc://{0}")]
    Ipc(String),

    /// In-memory connection
    #[display("{0}", alt = "inproc://{0}")]
    Inproc(String),
}

impl FromStr for ServiceAddr {
    type Err = ServiceAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split("://");
        Ok(match (split.next(), split.next(), split.next()) {
            (Some("tcp"), Some(s), None) => SocketAddr::from_str(s)?.into(),
            (Some("ipc"), Some(s), None) => ServiceAddr::Ipc(s.to_owned()),
            (Some("inproc"), Some(s), None) => {
                ServiceAddr::Inproc(s.to_owned())
            }
            (Some(s), None, _) if s.contains('/') => {
                ServiceAddr::Ipc(s.to_owned())
            }
            (Some(s), None, _) => SocketAddr::from_str(s)
                .map(ServiceAddr::from)
                .unwrap_or_else(|_| ServiceAddr::Inproc(s.to_owned())),
            _ => return Err(ServiceAddrParseError::Unrecognized(s.to_owned())),
        })
    }
}
