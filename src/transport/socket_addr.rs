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

//! Module supports transport-level addressing, i.e. the one used before
//! encryption/decryption of the actual data are taking place. These addresses
//! is mostly used internally and does not include information about node
//! public key (for that purpose you need to use session-level address
//! structures like [`crate::NodeAddr`]).

use std::cmp::Ordering;
#[cfg(feature = "url")]
use std::convert::TryFrom;
#[cfg(any(feature = "url", feature = "zmq"))]
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[cfg(feature = "url")]
use inet2_addr::InetAddr;
use inet2_addr::{InetSocketAddr, NoOnionSupportError};
#[cfg(all(feature = "serde", feature = "zmq"))]
use serde_with::{As, DisplayFromStr};
#[cfg(feature = "url")]
use url::{self, Url};

#[cfg(feature = "zmq")]
use super::zmqsocket;
use crate::{AddrError, UrlString};

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "UPPERCASE")
)]
#[non_exhaustive]
/// Possible transport-layer protocols with framing support
pub enum FramingProtocol {
    /// Framed raw LNP messages according to BOLT-8 pt. 2. Used with framed TCP
    /// socket connection.
    #[display("bolt", alt = "tcp")]
    Brontide,

    /// Framed raw LNP messages according to LNPBP-18. Used with Framed TCP
    /// socket connection.
    #[display("bifrost", alt = "tcp")]
    Brontide3,

    /// Microservices connected using ZeroMQ protocol remotely (ZeroMQ
    /// Transport Protocol). Used with both IPC, Inproc and TCP-based SMQ
    /// connections.
    #[cfg(feature = "zmq")]
    #[display("i2z", alt = "zmq")]
    I2z,
}

impl FromStr for FramingProtocol {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bolt" => Ok(FramingProtocol::Brontide),
            "bifrost" => Ok(FramingProtocol::Brontide3),
            #[cfg(feature = "zmq")]
            "i2z" | "zmtp" | "zmq" | "ipc" | "posix" | "unix" => {
                Ok(FramingProtocol::I2z)
            }
            other => Err(AddrError::UnknownProtocol(other.to_owned())),
        }
    }
}

/// Represents a connection that requires the other peer to be present on the
/// same machine as a connecting peer
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode
)]
pub enum LocalSocketAddr {
    /// Microservices connected using ZeroMQ protocol locally
    #[cfg(feature = "zmq")]
    #[display("{0}", alt = "lnpz://{0}")]
    Zmq(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        zmqsocket::ZmqSocketAddr,
    ),

    /// Local node operating as a separate **process** or **threads** connected
    /// with unencrypted POSIX file I/O (like in c-lightning)
    #[display("{0}", alt = "lnp:{0}")]
    Posix(String),
}

/// Represents a connection to a generic remote peer operating with Internet2
/// protocol
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode
)]
#[non_exhaustive]
pub enum RemoteSocketAddr {
    /// Brontide TCP socket connection as defined in BOLT-8, that may be served
    /// either over plain IP, IPSec or Tor v3
    #[display("{0}", alt = "bolt://{0}")]
    Bolt(InetSocketAddr),

    /// Brontide TCP socket connection as defined in Bifrost, that may be
    /// served either over plain IP, IPSec or Tor v3
    #[display("{0}", alt = "bifrost://{0}")]
    Bifrost(InetSocketAddr),

    /// Microservices connected using ZeroMQ protocol remotely. Can be used
    /// only with TCP-based ZMQ
    #[cfg(feature = "zmq")]
    #[display("{0}", alt = "i2z://{0}")]
    I2z(SocketAddr),
}

// Fake implementation required to use node addresses with StrictEncode
// BTreeMaps
impl PartialOrd for RemoteSocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_string().partial_cmp(&other.to_string())
    }
}

impl Ord for RemoteSocketAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl RemoteSocketAddr {
    pub fn with_ip_addr(proto: FramingProtocol, ip: IpAddr, port: u16) -> Self {
        let addr = SocketAddr::new(ip, port);
        Self::with_socket_addr(proto, addr)
    }

    pub fn with_socket_addr(proto: FramingProtocol, addr: SocketAddr) -> Self {
        match proto {
            FramingProtocol::Brontide => Self::Bolt(addr.into()),
            FramingProtocol::Brontide3 => Self::Bifrost(addr.into()),
            #[cfg(feature = "zmq")]
            FramingProtocol::I2z => Self::I2z(addr),
        }
    }

    pub fn with_inet_addr(
        proto: FramingProtocol,
        addr: InetSocketAddr,
    ) -> Result<Self, NoOnionSupportError> {
        Ok(match proto {
            FramingProtocol::Brontide => Self::Bolt(addr),
            FramingProtocol::Brontide3 => Self::Bifrost(addr),
            #[cfg(all(feature = "zmq", feature = "tor"))]
            FramingProtocol::I2z => Self::I2z(addr.try_into()?),
            #[cfg(all(feature = "zmq", not(feature = "tor")))]
            FramingProtocol::I2z => {
                Self::I2z(addr.try_into().map_err(|_| NoOnionSupportError)?)
            }
        })
    }

    pub fn framing_protocol(&self) -> FramingProtocol {
        match self {
            RemoteSocketAddr::Bolt(_) => FramingProtocol::Brontide,
            RemoteSocketAddr::Bifrost(_) => FramingProtocol::Brontide3,
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::I2z(_) => FramingProtocol::I2z,
        }
    }
}

impl From<RemoteSocketAddr> for InetSocketAddr {
    fn from(rsa: RemoteSocketAddr) -> Self {
        match rsa {
            RemoteSocketAddr::Bolt(inet) | RemoteSocketAddr::Bifrost(inet) => {
                inet
            }
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::I2z(sa) => sa.into(),
        }
    }
}

#[cfg(feature = "url")]
impl FromStr for LocalSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

#[cfg(not(feature = "url"))]
impl FromStr for LocalSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        panic!("Parsing LocalSocketAddr from string requires url feature")
    }
}

#[cfg(feature = "url")]
impl FromStr for RemoteSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

#[cfg(not(feature = "url"))]
impl FromStr for RemoteSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        panic!("Parsing RemoteSocketAddr from string requires url feature")
    }
}

impl UrlString for LocalSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(zmqsocket::ZmqSocketAddr::Tcp(..)) => {
                "lnpz://"
            }
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(_) => "lnpz:",
            LocalSocketAddr::Posix(_) => "lnp:",
        }
    }

    fn to_url_string(&self) -> String { format!("{:#}", self) }
}

impl UrlString for RemoteSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::I2z(_) => "i2z://",
            RemoteSocketAddr::Bolt(_) => "bolt://",
            RemoteSocketAddr::Bifrost(_) => "bifrost://",
        }
    }

    fn to_url_string(&self) -> String { format!("{:#}", self) }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for LocalSocketAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        Ok(match url.scheme() {
            "lnp" => {
                if url.host().is_some() {
                    return Err(AddrError::UnexpectedHost);
                } else if url.has_authority() {
                    return Err(AddrError::UnexpectedAuthority);
                } else if url.port().is_some() {
                    return Err(AddrError::UnexpectedPort);
                }
                LocalSocketAddr::Posix(url.path().to_owned())
            }
            #[cfg(feature = "zmq")]
            "lnpz" => {
                LocalSocketAddr::Zmq(zmqsocket::ZmqSocketAddr::try_from(url)?)
            }
            "lnph" | "lnpws" | "lnpm" => {
                return Err(AddrError::Unsupported("for local socket address"))
            }
            other => return Err(AddrError::UnknownUrlScheme(other.to_owned())),
        })
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for RemoteSocketAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let host = url.host_str().ok_or(AddrError::HostRequired)?.to_owned();
        let inet_addr = host.parse::<InetAddr>()?;
        let port = url.port().ok_or(AddrError::PortRequired)?;
        let inet_socket_addr = InetSocketAddr::new(inet_addr, port);
        Ok(match url.scheme() {
            "bolt" => RemoteSocketAddr::Bolt(inet_socket_addr),
            "bifrost" => RemoteSocketAddr::Bifrost(inet_socket_addr),
            #[cfg(all(feature = "zmq", feature = "tor"))]
            "i2z" => RemoteSocketAddr::I2z(inet_socket_addr.try_into()?),
            #[cfg(all(feature = "zmq", not(feature = "tor")))]
            "i2z" => RemoteSocketAddr::I2z(
                inet_socket_addr
                    .try_into()
                    .map_err(|_| AddrError::NoOnionSupport)?,
            ),
            other => return Err(AddrError::UnknownUrlScheme(other.to_owned())),
        })
    }
}
