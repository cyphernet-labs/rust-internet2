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

use std::cmp::Ordering;
#[cfg(feature = "tor")]
use std::convert::TryFrom;
use std::fmt;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::num::ParseIntError;
use std::str::FromStr;

#[cfg(feature = "tor")]
use torut::onion::OnionAddressV3;

/// Address type do not support ONION address format and can be used only with
/// IPv4 or IPv6 addresses
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct NoOnionSupportError;

/// Errors during address string parse process
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddrParseError {
    /// Wrong port number; must be a 16-bit unsigned integer number
    #[from(ParseIntError)]
    WrongPortNumber,

    /// Can't recognize IPv4, v6 or Onion v2/v3 address in string "{_0}"
    WrongAddrFormat(String),

    /// Wrong format of socket address string "{_0}"; use
    /// \<inet_address\>\[:\<port\>\]
    WrongSocketFormat(String),

    /// Wrong format of extended socket address string "{_0}"; use
    /// \<transport\>://\<inet_address\>\[:\<port\>\]
    WrongSocketExtFormat(String),

    /// Unknown transport protocol "{_0}"
    UnknownProtocolError(String),

    /// Error parsing onion address
    #[cfg(feature = "tor")]
    #[display(inner)]
    #[from]
    OnionAddressError(torut::onion::OnionAddressParseError),

    /// Tor addresses are not supported; consider compiling with `tor` feature
    #[from(NoOnionSupportError)]
    NeedsTorFeature,
}

/// A universal address covering IPv4, IPv6 and Tor in a single byte sequence
/// of 32 bytes.
///
/// Holds either:
/// * IPv4-to-IPv6 address
/// * IPv6 address
/// * Tor Onion address (V3 only)
///
#[derive(Clone, Copy, PartialEq, Eq, Debug, From, Display)]
#[cfg_attr(
    all(feature = "serde", feature = "serde_str_helpers"),
    derive(Serialize, Deserialize),
    serde(
        try_from = "serde_str_helpers::DeserBorrowStr",
        into = "String",
        crate = "serde_crate"
    )
)]
#[cfg_attr(
    all(feature = "serde", not(feature = "serde_str_helpers")),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(inner)]
#[non_exhaustive] // Required since we use feature-gated enum variants
pub enum InetAddr {
    /// IP address of V4 standard
    #[from]
    IPv4(Ipv4Addr),

    /// IP address of V6 standard
    #[from]
    IPv6(Ipv6Addr),

    /// Tor address of V3 standard
    #[cfg(feature = "tor")]
    #[from]
    Tor(OnionAddressV3),
}

impl PartialOrd for InetAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (InetAddr::IPv4(addr1), InetAddr::IPv4(addr2)) => {
                addr1.partial_cmp(addr2)
            }
            (InetAddr::IPv6(addr1), InetAddr::IPv6(addr2)) => {
                addr1.partial_cmp(addr2)
            }
            #[cfg(feature = "tor")]
            (InetAddr::Tor(addr1), InetAddr::Tor(addr2)) => {
                addr1.get_public_key().partial_cmp(&addr2.get_public_key())
            }
            (InetAddr::IPv4(_), _) => Some(Ordering::Greater),
            (_, InetAddr::IPv4(_)) => Some(Ordering::Less),
            #[cfg(feature = "tor")]
            (InetAddr::IPv6(_), _) => Some(Ordering::Greater),
            #[cfg(feature = "tor")]
            (_, InetAddr::IPv6(_)) => Some(Ordering::Less),
        }
    }
}

impl Ord for InetAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

// We need this since OnionAddressV3 does not implement Hash
#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for InetAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            InetAddr::IPv4(ipv4) => ipv4.hash(state),
            InetAddr::IPv6(ipv6) => ipv6.hash(state),
            #[cfg(feature = "tor")]
            InetAddr::Tor(torv3) => {
                torv3.get_public_key().as_bytes().hash(state)
            }
        }
    }
}

impl InetAddr {
    /// Returns an IPv6 address, constructed from IPv4 data; or, if Onion
    /// address is used, [`Option::None`]
    #[inline]
    pub fn ipv6_addr(self) -> Option<Ipv6Addr> {
        match self {
            InetAddr::IPv4(ipv4_addr) => Some(ipv4_addr.to_ipv6_mapped()),
            InetAddr::IPv6(ipv6_addr) => Some(ipv6_addr),
            #[cfg(feature = "tor")]
            _ => None,
        }
    }

    /// Returns an IPv4 address, if any, or [`Option::None`]
    #[inline]
    pub fn ipv4_addr(self) -> Option<Ipv4Addr> {
        match self {
            InetAddr::IPv4(ipv4_addr) => Some(ipv4_addr),
            InetAddr::IPv6(ipv6_addr) => ipv6_addr.to_ipv4(),
            #[cfg(feature = "tor")]
            _ => None,
        }
    }

    /// Determines whether provided address is a Tor address. Always returns
    /// `false` (the library is built without `tor` feature; use it to
    /// enable Tor addresses).
    #[cfg(not(feature = "tor"))]
    #[inline]
    pub fn is_tor(self) -> bool {
        false
    }

    /// Always returns [`Option::None`] (the library is built without `tor`
    /// feature; use it to enable Tor addresses).
    #[cfg(not(feature = "tor"))]
    #[inline]
    pub fn onion_address(self) -> Option<()> {
        None
    }

    /// Determines whether provided address is a Tor address
    #[cfg(feature = "tor")]
    #[inline]
    pub fn is_tor(self) -> bool {
        matches!(self, InetAddr::Tor(_))
    }

    /// Returns Onion v3 address, if any, or [`Option::None`]
    #[cfg(feature = "tor")]
    #[inline]
    pub fn onion_address(self) -> Option<OnionAddressV3> {
        match self {
            InetAddr::IPv4(_) | InetAddr::IPv6(_) => None,
            InetAddr::Tor(onion) => Some(onion),
        }
    }
}

impl Default for InetAddr {
    #[inline]
    fn default() -> Self {
        InetAddr::IPv4(Ipv4Addr::from(0))
    }
}

#[cfg(feature = "tor")]
impl TryFrom<InetAddr> for IpAddr {
    type Error = NoOnionSupportError;
    #[inline]
    fn try_from(addr: InetAddr) -> Result<Self, Self::Error> {
        Ok(match addr {
            InetAddr::IPv4(addr) => IpAddr::V4(addr),
            InetAddr::IPv6(addr) => IpAddr::V6(addr),
            #[cfg(feature = "tor")]
            InetAddr::Tor(_) => return Err(NoOnionSupportError),
        })
    }
}

#[cfg(not(feature = "tor"))]
impl From<InetAddr> for IpAddr {
    #[inline]
    fn from(addr: InetAddr) -> Self {
        match addr {
            InetAddr::IPv4(addr) => IpAddr::V4(addr),
            InetAddr::IPv6(addr) => IpAddr::V6(addr),
        }
    }
}

impl From<IpAddr> for InetAddr {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => InetAddr::from(v4),
            IpAddr::V6(v6) => InetAddr::from(v6),
        }
    }
}

#[cfg(feature = "stringly_conversions")]
impl_try_from_stringly_standard!(InetAddr);
#[cfg(feature = "stringly_conversions")]
impl_into_stringly_standard!(InetAddr);

impl FromStr for InetAddr {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(feature = "tor")]
        match (IpAddr::from_str(s), OnionAddressV3::from_str(s)) {
            (Ok(_), Ok(_)) => {
                Err(AddrParseError::WrongAddrFormat(s.to_owned()))
            }
            (Ok(ip_addr), _) => Ok(Self::from(ip_addr)),
            (_, Ok(onionv3)) => Ok(Self::from(onionv3)),
            _ => Err(AddrParseError::WrongAddrFormat(s.to_owned())),
        }

        #[cfg(not(feature = "tor"))]
        match IpAddr::from_str(s) {
            Ok(ip_addr) => Ok(InetAddr::from(ip_addr)),
            _ => Err(AddrParseError::NeedsTorFeature),
        }
    }
}

// Yes, I checked that onion addresses don't need to optimize ownership of input
// String.
#[cfg(feature = "parse_arg")]
impl parse_arg::ParseArgFromStr for InetAddr {
    fn describe_type<W: std::fmt::Write>(mut writer: W) -> std::fmt::Result {
        #[cfg(not(feature = "tor"))]
        {
            write!(writer, "IPv4 or IPv6 address")
        }
        #[cfg(feature = "tor")]
        {
            write!(writer, "IPv4, IPv6, or Tor (onion) address")
        }
    }
}

impl From<[u8; 4]> for InetAddr {
    #[inline]
    fn from(value: [u8; 4]) -> Self {
        InetAddr::from(Ipv4Addr::from(value))
    }
}

impl From<[u8; 16]> for InetAddr {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

impl From<[u16; 8]> for InetAddr {
    #[inline]
    fn from(value: [u16; 8]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

/// A universal address covering IPv4, IPv6 and Tor in a single byte sequence
/// of 32 bytes, which may contain optional port number part.
#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
#[cfg_attr(
    all(feature = "serde", feature = "serde_str_helpers"),
    derive(Serialize, Deserialize),
    serde(
        try_from = "serde_str_helpers::DeserBorrowStr",
        into = "String",
        crate = "serde_crate"
    )
)]
#[cfg_attr(
    all(feature = "serde", not(feature = "serde_str_helpers")),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[non_exhaustive] // Required since we use feature-gated enum variants
pub enum PartialSocketAddr {
    /// IP address of V4 standard with optional port number
    IPv4(Ipv4Addr, Option<u16>),

    /// IP address of V6 standard with optional port number
    IPv6(Ipv6Addr, Option<u16>),

    /// Tor address of V3 standard with optional port number
    #[cfg(feature = "tor")]
    Tor(OnionAddressV3, Option<u16>),
}

impl PartialOrd for PartialSocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (
                PartialSocketAddr::IPv4(addr1, Some(port1)),
                PartialSocketAddr::IPv4(addr2, Some(port2)),
            ) => SocketAddrV4::new(*addr1, *port1)
                .partial_cmp(&SocketAddrV4::new(*addr2, *port2)),
            (
                PartialSocketAddr::IPv6(addr1, Some(port1)),
                PartialSocketAddr::IPv6(addr2, Some(port2)),
            ) => SocketAddrV6::new(*addr1, *port1, 0, 0)
                .partial_cmp(&SocketAddrV6::new(*addr2, *port2, 0, 0)),
            #[cfg(feature = "tor")]
            (
                PartialSocketAddr::Tor(addr1, Some(port1)),
                PartialSocketAddr::Tor(addr2, Some(port2)),
            ) => TorAddrV3::new(*addr1, *port1)
                .partial_cmp(&TorAddrV3::new(*addr2, *port2)),
            (
                PartialSocketAddr::IPv4(addr1, Some(port1)),
                PartialSocketAddr::IPv4(addr2, None),
            ) => SocketAddrV4::new(*addr1, *port1)
                .partial_cmp(&SocketAddrV4::new(*addr2, 0)),
            (
                PartialSocketAddr::IPv6(addr1, Some(port1)),
                PartialSocketAddr::IPv6(addr2, None),
            ) => SocketAddrV6::new(*addr1, *port1, 0, 0)
                .partial_cmp(&SocketAddrV6::new(*addr2, 0, 0, 0)),
            #[cfg(feature = "tor")]
            (
                PartialSocketAddr::Tor(addr1, Some(port1)),
                PartialSocketAddr::Tor(addr2, None),
            ) => TorAddrV3::new(*addr1, *port1)
                .partial_cmp(&TorAddrV3::new(*addr2, 0)),
            (
                PartialSocketAddr::IPv4(addr1, None),
                PartialSocketAddr::IPv4(addr2, Some(port2)),
            ) => SocketAddrV4::new(*addr1, 0)
                .partial_cmp(&SocketAddrV4::new(*addr2, *port2)),
            (
                PartialSocketAddr::IPv6(addr1, None),
                PartialSocketAddr::IPv6(addr2, Some(port2)),
            ) => SocketAddrV6::new(*addr1, 0, 0, 0)
                .partial_cmp(&SocketAddrV6::new(*addr2, *port2, 0, 0)),
            #[cfg(feature = "tor")]
            (
                PartialSocketAddr::Tor(addr1, None),
                PartialSocketAddr::Tor(addr2, Some(port2)),
            ) => TorAddrV3::new(*addr1, 0)
                .partial_cmp(&TorAddrV3::new(*addr2, *port2)),
            (
                PartialSocketAddr::IPv4(addr1, None),
                PartialSocketAddr::IPv4(addr2, None),
            ) => addr1.partial_cmp(addr2),
            (
                PartialSocketAddr::IPv6(addr1, None),
                PartialSocketAddr::IPv6(addr2, None),
            ) => addr1.partial_cmp(addr2),
            #[cfg(feature = "tor")]
            (
                PartialSocketAddr::Tor(addr1, None),
                PartialSocketAddr::Tor(addr2, None),
            ) => TorAddrV3::new(*addr1, 0)
                .partial_cmp(&TorAddrV3::new(*addr2, 0)),
            (PartialSocketAddr::IPv4(_, _), _) => Some(Ordering::Greater),
            (_, PartialSocketAddr::IPv4(_, _)) => Some(Ordering::Less),
            #[cfg(feature = "tor")]
            (PartialSocketAddr::IPv6(_, _), _) => Some(Ordering::Greater),
            #[cfg(feature = "tor")]
            (_, PartialSocketAddr::IPv6(_, _)) => Some(Ordering::Less),
        }
    }
}

impl Ord for PartialSocketAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

// We need this since OnionAddressV3 does not implement Hash
#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for PartialSocketAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            PartialSocketAddr::IPv4(ipv4, port) => {
                ipv4.hash(state);
                port.hash(state)
            }
            PartialSocketAddr::IPv6(ipv6, port) => {
                ipv6.hash(state);
                port.hash(state)
            }
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(torv3, port) => {
                torv3.get_public_key().as_bytes().hash(state);
                port.hash(state);
            }
        }
    }
}

impl PartialSocketAddr {
    /// Constructs new socket address matching the provided Tor v3 address
    #[cfg(feature = "tor")]
    #[inline]
    pub fn tor3(tor: OnionAddressV3, port: Option<u16>) -> Self {
        PartialSocketAddr::Tor(tor, port)
    }

    /// Constructs new socket address from an internet address and a port
    /// information
    #[inline]
    pub fn socket(ip: IpAddr, port: Option<u16>) -> Self {
        match ip {
            IpAddr::V4(ipv4) => PartialSocketAddr::IPv4(ipv4, port),
            IpAddr::V6(ipv6) => PartialSocketAddr::IPv6(ipv6, port),
        }
    }

    /// Determines whether provided address is a Tor address. Always returns
    /// `false` (the library is built without `tor` feature; use it to
    /// enable Tor addresses).
    #[cfg(not(feature = "tor"))]
    #[inline]
    pub fn is_tor(self) -> bool {
        false
    }

    /// Always returns [`Option::None`] (the library is built without `tor`
    /// feature; use it to enable Tor addresses).
    #[cfg(not(feature = "tor"))]
    #[inline]
    pub fn onion_address(self) -> Option<()> {
        None
    }

    /// Determines whether provided address is a Tor address
    #[cfg(feature = "tor")]
    #[inline]
    pub fn is_tor(self) -> bool {
        matches!(self, PartialSocketAddr::Tor(_, _))
    }

    /// Returns Onion v3 address, if any, or [`Option::None`]
    #[cfg(feature = "tor")]
    #[inline]
    pub fn onion_address(self) -> Option<OnionAddressV3> {
        match self {
            PartialSocketAddr::IPv4(_, _) | PartialSocketAddr::IPv6(_, _) => {
                None
            }
            PartialSocketAddr::Tor(onion, _) => Some(onion),
        }
    }

    /// Returns [`InetAddr`] address of the socket
    #[inline]
    pub fn address(self) -> InetAddr {
        match self {
            PartialSocketAddr::IPv4(addr, _) => InetAddr::IPv4(addr),
            PartialSocketAddr::IPv6(addr, _) => InetAddr::IPv6(addr),
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(onion, _) => InetAddr::Tor(onion),
        }
    }

    /// Returns port for the socket, if address allows different ports.
    #[inline]
    pub fn port(self) -> Option<u16> {
        match self {
            PartialSocketAddr::IPv4(_, port)
            | PartialSocketAddr::IPv6(_, port) => port,
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(_, _) => None,
        }
    }

    /// Constructs [`InetSocketAddr`] using default port information.
    pub fn inet_socket(self, default_port: u16) -> InetSocketAddr {
        match self {
            PartialSocketAddr::IPv4(addr, None) => {
                InetSocketAddr::IPv4(SocketAddrV4::new(addr, default_port))
            }
            PartialSocketAddr::IPv6(addr, None) => InetSocketAddr::IPv6(
                SocketAddrV6::new(addr, default_port, 0, 0),
            ),
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(addr, None) => {
                InetSocketAddr::Tor(TorAddrV3::new(addr, default_port))
            }
            PartialSocketAddr::IPv4(addr, Some(port)) => {
                InetSocketAddr::IPv4(SocketAddrV4::new(addr, port))
            }
            PartialSocketAddr::IPv6(addr, Some(port)) => {
                InetSocketAddr::IPv6(SocketAddrV6::new(addr, port, 0, 0))
            }
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(addr, Some(port)) => {
                InetSocketAddr::Tor(TorAddrV3::new(addr, port))
            }
        }
    }
}

impl Default for PartialSocketAddr {
    #[inline]
    fn default() -> Self {
        PartialSocketAddr::IPv4(Ipv4Addr::from(0), None)
    }
}

#[cfg(feature = "tor")]
impl TryFrom<PartialSocketAddr> for IpAddr {
    type Error = NoOnionSupportError;
    #[inline]
    fn try_from(addr: PartialSocketAddr) -> Result<Self, Self::Error> {
        Ok(match addr {
            PartialSocketAddr::IPv4(addr, _) => IpAddr::V4(addr),
            PartialSocketAddr::IPv6(addr, _) => IpAddr::V6(addr),
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(_, _) => return Err(NoOnionSupportError),
        })
    }
}

impl From<IpAddr> for PartialSocketAddr {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => PartialSocketAddr::from(v4),
            IpAddr::V6(v6) => PartialSocketAddr::from(v6),
        }
    }
}

impl From<Ipv4Addr> for PartialSocketAddr {
    #[inline]
    fn from(value: Ipv4Addr) -> Self {
        PartialSocketAddr::IPv4(value, None)
    }
}

impl From<Ipv6Addr> for PartialSocketAddr {
    #[inline]
    fn from(value: Ipv6Addr) -> Self {
        PartialSocketAddr::IPv6(value, None)
    }
}

impl From<SocketAddr> for PartialSocketAddr {
    #[inline]
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(v4) => PartialSocketAddr::from(v4),
            SocketAddr::V6(v6) => PartialSocketAddr::from(v6),
        }
    }
}

impl From<SocketAddrV4> for PartialSocketAddr {
    #[inline]
    fn from(value: SocketAddrV4) -> Self {
        PartialSocketAddr::IPv4(*value.ip(), Some(value.port()))
    }
}

impl From<SocketAddrV6> for PartialSocketAddr {
    #[inline]
    fn from(value: SocketAddrV6) -> Self {
        PartialSocketAddr::IPv6(*value.ip(), Some(value.port()))
    }
}

#[cfg(feature = "tor")]
impl From<OnionAddressV3> for PartialSocketAddr {
    #[inline]
    fn from(addr: OnionAddressV3) -> Self {
        PartialSocketAddr::Tor(addr, None)
    }
}

impl From<InetAddr> for PartialSocketAddr {
    fn from(addr: InetAddr) -> Self {
        match addr {
            InetAddr::IPv4(addr) => PartialSocketAddr::IPv4(addr, None),
            InetAddr::IPv6(addr) => PartialSocketAddr::IPv6(addr, None),
            #[cfg(feature = "tor")]
            InetAddr::Tor(addr) => PartialSocketAddr::Tor(addr, None),
        }
    }
}

impl From<InetSocketAddr> for PartialSocketAddr {
    fn from(addr: InetSocketAddr) -> Self {
        match addr {
            InetSocketAddr::IPv4(socket) => {
                PartialSocketAddr::IPv4(*socket.ip(), Some(socket.port()))
            }
            InetSocketAddr::IPv6(socket) => {
                PartialSocketAddr::IPv6(*socket.ip(), Some(socket.port()))
            }
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(tor) => {
                PartialSocketAddr::Tor(tor.onion_address, Some(tor.port))
            }
        }
    }
}

impl fmt::Display for PartialSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PartialSocketAddr::IPv4(addr, None) => fmt::Display::fmt(addr, f),
            PartialSocketAddr::IPv6(addr, None) => fmt::Display::fmt(addr, f),
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(addr, None) => fmt::Display::fmt(addr, f),
            PartialSocketAddr::IPv4(addr, Some(port)) => {
                fmt::Display::fmt(&SocketAddrV4::new(*addr, *port), f)
            }
            PartialSocketAddr::IPv6(addr, Some(port)) => {
                fmt::Display::fmt(&SocketAddrV6::new(*addr, *port, 0, 0), f)
            }
            #[cfg(feature = "tor")]
            PartialSocketAddr::Tor(addr, Some(port)) => {
                fmt::Display::fmt(&TorAddrV3::new(*addr, *port), f)
            }
        }
    }
}

#[cfg(feature = "stringly_conversions")]
impl_try_from_stringly_standard!(PartialSocketAddr);
#[cfg(feature = "stringly_conversions")]
impl_into_stringly_standard!(PartialSocketAddr);

impl FromStr for PartialSocketAddr {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(not(feature = "tor"))]
        struct OnionAddressV3;
        #[cfg(not(feature = "tor"))]
        impl OnionAddressV3 {
            fn from_str(_: &str) -> Result<Self, AddrParseError> {
                Err(AddrParseError::NeedsTorFeature)
            }
        }

        match (
            SocketAddr::from_str(s),
            IpAddr::from_str(s),
            OnionAddressV3::from_str(s),
        ) {
            (Ok(_), _, Ok(_)) | (_, Ok(_), Ok(_)) => {
                Err(AddrParseError::WrongAddrFormat(s.to_owned()))
            }
            (Ok(socket_addr), ..) => Ok(Self::from(socket_addr)),
            (_, Ok(ip_addr), _) => Ok(Self::from(ip_addr)),
            #[cfg(feature = "tor")]
            (_, _, Ok(onionv3)) => Ok(Self::from(onionv3)),
            (_, _, Err(err)) => Err(err.into()),
            #[cfg(not(feature = "tor"))]
            _ => Err(AddrParseError::WrongAddrFormat(s.to_owned())),
        }
    }
}

#[cfg(feature = "parse_arg")]
impl parse_arg::ParseArgFromStr for PartialSocketAddr {
    fn describe_type<W: std::fmt::Write>(mut writer: W) -> std::fmt::Result {
        #[cfg(not(feature = "tor"))]
        {
            write!(writer, "IPv4 or IPv6 address with optional port")
        }
        #[cfg(feature = "tor")]
        {
            write!(
                writer,
                "IPv4, IPv6, or Tor (onion) address with optional port"
            )
        }
    }
}

/// Transport protocols that may be part of [`InetSocketAddrExt`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum Transport {
    /// Normal TCP
    #[display("tcp")]
    Tcp = 1,

    /// Normal UDP
    #[display("udp")]
    Udp = 2,

    /// Multipath TCP version
    #[display("mtcp")]
    Mtcp = 3,

    /// More efficient UDP version under developent by Google and consortium of
    /// other internet companies
    #[display("quic")]
    Quic = 4,
    /* There are other rarely used protocols. Do not see any reason to add
     * them to the crate for now, but it may appear in the future,
     * so keeping them for referencing purposes: */
    /*
    UdpLite,
    Sctp,
    Dccp,
    Rudp,
    */
}

impl Default for Transport {
    #[inline]
    fn default() -> Self {
        Transport::Tcp
    }
}

impl FromStr for Transport {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "udp" => Transport::Udp,
            "mtcp" => Transport::Mtcp,
            "quic" => Transport::Quic,
            _ => {
                return Err(AddrParseError::UnknownProtocolError(s.to_owned()))
            }
        })
    }
}

/// Internet socket address, which consists of [`InetAddr`] IP or Tor address
/// and a port number (without protocol specification, i.e. TCP/UDP etc). If you
/// need to include transport-level protocol information into the socket
/// details, pls check [`InetSocketAddrExt`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Display, From)]
#[cfg_attr(
    all(feature = "serde", feature = "serde_str_helpers"),
    derive(Serialize, Deserialize),
    serde(
        try_from = "serde_str_helpers::DeserBorrowStr",
        into = "String",
        crate = "serde_crate"
    )
)]
#[cfg_attr(
    all(feature = "serde", not(feature = "serde_str_helpers")),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(inner)]
#[non_exhaustive] // Required since we use feature-gated enum variants
pub enum InetSocketAddr {
    /// IP socket address of V4 standard
    #[from]
    IPv4(SocketAddrV4),

    /// IP socket address of V6 standard
    #[from]
    IPv6(SocketAddrV6),

    /// Tor address of V3 standard
    #[cfg(feature = "tor")]
    #[from]
    Tor(TorAddrV3),
}

#[derive(Copy, Clone, Display, Eq, PartialEq, Debug)]
#[cfg_attr(
    all(feature = "serde", feature = "serde_str_helpers"),
    derive(Serialize, Deserialize),
    serde(
        try_from = "serde_str_helpers::DeserBorrowStr",
        into = "String",
        crate = "serde_crate"
    )
)]
#[cfg_attr(
    all(feature = "serde", not(feature = "serde_str_helpers")),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[cfg(feature = "tor")]
#[display("{onion_address}:{port}")]
pub struct TorAddrV3 {
    pub onion_address: OnionAddressV3,
    pub port: u16,
}

#[cfg(feature = "tor")]
impl TorAddrV3 {
    pub fn new(onion_address: OnionAddressV3, port: u16) -> TorAddrV3 {
        TorAddrV3 {
            onion_address,
            port,
        }
    }
}

#[cfg(feature = "tor")]
impl FromStr for TorAddrV3 {
    type Err = AddrParseError;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let (str_addr, str_port) =
            str.split_once(':')
                .ok_or(AddrParseError::WrongSocketFormat(
                "Tor address needs to be formatted as <onion_address>:<port>"
                    .to_string(),
            ))?;
        let onion_address = OnionAddressV3::from_str(&str_addr)?;
        let port = u16::from_str(&str_port)?;
        Ok(TorAddrV3::new(onion_address, port))
    }
}

#[cfg(feature = "tor")]
impl PartialOrd for TorAddrV3 {
    fn partial_cmp(&self, other: &TorAddrV3) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "tor")]
impl Ord for TorAddrV3 {
    fn cmp(&self, other: &TorAddrV3) -> Ordering {
        self.onion_address
            .get_public_key()
            .cmp(&other.onion_address.get_public_key())
            .then(self.port.cmp(&other.port))
    }
}

impl PartialOrd for InetSocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (InetSocketAddr::IPv4(addr1), InetSocketAddr::IPv4(addr2)) => {
                addr1.partial_cmp(addr2)
            }
            (InetSocketAddr::IPv6(addr1), InetSocketAddr::IPv6(addr2)) => {
                addr1.partial_cmp(addr2)
            }
            #[cfg(feature = "tor")]
            (InetSocketAddr::Tor(addr1), InetSocketAddr::Tor(addr2)) => {
                addr1.partial_cmp(addr2)
            }
            (InetSocketAddr::IPv4(_), _) => Some(Ordering::Greater),
            (_, InetSocketAddr::IPv4(_)) => Some(Ordering::Less),
            #[cfg(feature = "tor")]
            (InetSocketAddr::IPv6(_), _) => Some(Ordering::Greater),
            #[cfg(feature = "tor")]
            (_, InetSocketAddr::IPv6(_)) => Some(Ordering::Less),
        }
    }
}

impl Ord for InetSocketAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

// We need this since OnionAddressV3 does not implement Hash
#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for InetSocketAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            InetSocketAddr::IPv4(socketv4) => socketv4.hash(state),
            InetSocketAddr::IPv6(socketv6) => socketv6.hash(state),
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(tor_addr) => {
                tor_addr
                    .onion_address
                    .get_public_key()
                    .as_bytes()
                    .hash(state);
                tor_addr.port.hash(state);
            }
        }
    }
}

impl Default for InetSocketAddr {
    #[inline]
    fn default() -> Self {
        InetSocketAddr::IPv4(SocketAddrV4::new(Ipv4Addr::from(0), 0))
    }
}

impl InetSocketAddr {
    /// Constructs new socket address matching the provided Tor v3 address
    #[cfg(feature = "tor")]
    #[inline]
    pub fn tor3(onion_address: OnionAddressV3, port: u16) -> Self {
        InetSocketAddr::Tor(TorAddrV3::new(onion_address, port))
    }

    /// Constructs new socket address from an internet address and a port
    /// information
    #[inline]
    pub fn socket(ip: IpAddr, port: u16) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                InetSocketAddr::IPv4(SocketAddrV4::new(ipv4, port))
            }
            IpAddr::V6(ipv6) => {
                InetSocketAddr::IPv6(SocketAddrV6::new(ipv6, port, 0, 0))
            }
        }
    }

    /// Determines whether provided address is a Tor address
    #[inline]
    pub fn is_tor(&self) -> bool {
        match self {
            InetSocketAddr::IPv4(_) | InetSocketAddr::IPv6(_) => false,
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(_) => true,
        }
    }

    /// Returns [`InetAddr`] address of the socket
    #[inline]
    pub fn address(self) -> InetAddr {
        match self {
            InetSocketAddr::IPv4(socket) => InetAddr::IPv4(*socket.ip()),
            InetSocketAddr::IPv6(socket) => InetAddr::IPv6(*socket.ip()),
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(tor) => InetAddr::Tor(tor.onion_address),
        }
    }

    /// Returns port for the socket, if address allows different ports.
    ///
    /// Returns `None` for portless addresses (Tor etc).
    #[inline]
    pub fn port(self) -> Option<u16> {
        match self {
            InetSocketAddr::IPv4(socket) => Some(socket.port()),
            InetSocketAddr::IPv6(socket) => Some(socket.port()),
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(_) => None,
        }
    }
}

#[cfg(feature = "stringly_conversions")]
impl_try_from_stringly_standard!(InetSocketAddr);
#[cfg(feature = "stringly_conversions")]
impl_into_stringly_standard!(InetSocketAddr);

impl FromStr for InetSocketAddr {
    type Err = AddrParseError;

    #[allow(unreachable_code)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = SocketAddrV6::from_str(s) {
            Ok(InetSocketAddr::IPv6(socket_addr))
        } else if let Ok(socket_addr) = SocketAddrV4::from_str(s) {
            Ok(InetSocketAddr::IPv4(socket_addr))
        } else {
            #[cfg(not(feature = "tor"))]
            {
                Err(AddrParseError::NeedsTorFeature)
            }
            #[cfg(feature = "tor")]
            if let Ok(addr) = TorAddrV3::from_str(s) {
                Ok(InetSocketAddr::Tor(addr))
            } else {
                Err(AddrParseError::WrongAddrFormat(s.to_owned()))
            }
        }
    }
}

#[cfg(feature = "parse_arg")]
impl parse_arg::ParseArgFromStr for InetSocketAddr {
    fn describe_type<W: std::fmt::Write>(mut writer: W) -> std::fmt::Result {
        #[cfg(not(feature = "tor"))]
        {
            write!(writer, "IPv4 or IPv6 socket address")
        }
        #[cfg(feature = "tor")]
        {
            write!(writer, "IPv4, IPv6, or Tor (onion) socket address")
        }
    }
}

#[cfg(feature = "tor")]
impl TryFrom<InetSocketAddr> for SocketAddr {
    type Error = NoOnionSupportError;
    #[inline]
    fn try_from(socket_addr: InetSocketAddr) -> Result<Self, Self::Error> {
        match socket_addr {
            InetSocketAddr::IPv4(socket) => Ok(SocketAddr::V4(socket)),
            InetSocketAddr::IPv6(socket) => Ok(SocketAddr::V6(socket)),
            InetSocketAddr::Tor(_) => Err(NoOnionSupportError),
        }
    }
}

#[cfg(not(feature = "tor"))]
impl From<InetSocketAddr> for SocketAddr {
    #[inline]
    fn from(socket_addr: InetSocketAddr) -> Self {
        match socket_addr {
            InetSocketAddr::IPv4(socket) => SocketAddr::V4(socket),
            InetSocketAddr::IPv6(socket) => SocketAddr::V6(socket),
            #[cfg(feature = "tor")]
            InetSocketAddr::Tor(_) => unreachable!(),
        }
    }
}

impl From<SocketAddr> for InetSocketAddr {
    #[inline]
    fn from(socket: SocketAddr) -> Self {
        match socket {
            SocketAddr::V4(socket) => InetSocketAddr::IPv4(socket),
            SocketAddr::V6(socket) => InetSocketAddr::IPv6(socket),
        }
    }
}

/// Internet socket address of [`InetSocketAddr`] type, extended with a
/// transport-level protocol information (see [`Transport`])
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(
    all(feature = "serde", feature = "serde_str_helpers"),
    derive(Serialize, Deserialize),
    serde(
        try_from = "serde_str_helpers::DeserBorrowStr",
        into = "String",
        crate = "serde_crate"
    )
)]
#[cfg_attr(
    all(feature = "serde", not(feature = "serde_str_helpers")),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct InetSocketAddrExt(
    /// Transport-level protocol details (like TCP, UDP etc)
    pub Transport,
    /// Details of the socket address, i.e internet address and port
    /// information
    pub InetSocketAddr,
);

#[cfg(feature = "stringly_conversions")]
impl_try_from_stringly_standard!(InetSocketAddrExt);
#[cfg(feature = "stringly_conversions")]
impl_into_stringly_standard!(InetSocketAddrExt);

impl InetSocketAddrExt {
    /// Constructs [`InetSocketAddrExt`] for a given socket address and TCP
    /// port
    #[inline]
    pub fn tcp(socket: SocketAddr) -> Self {
        Self(Transport::Tcp, socket.into())
    }

    /// Constructs [`InetSocketAddrExt`] for a given internet address and UDP
    /// port
    #[inline]
    pub fn udp(address: IpAddr, port: u16) -> Self {
        Self(Transport::Udp, SocketAddr::new(address, port).into())
    }
}

impl fmt::Display for InetSocketAddrExt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.0, self.1)
    }
}

impl FromStr for InetSocketAddrExt {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vals = s.split("://");
        if let (Some(transport), Some(addr), None) =
            (vals.next(), vals.next(), vals.next())
        {
            Ok(Self(transport.parse()?, addr.parse()?))
        } else {
            Err(AddrParseError::WrongSocketExtFormat(s.to_owned()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // TODO: Add tests for Tor

    #[test]
    fn test_inet_addr() {
        let ip4a = "127.0.0.1".parse().unwrap();
        let ip6a = "::1".parse().unwrap();

        let ip4 = InetAddr::IPv4(ip4a);
        let ip6 = InetAddr::IPv6(ip6a);
        assert_eq!(
            ip4.ipv6_addr().unwrap(),
            Ipv6Addr::from_str("::ffff:127.0.0.1").unwrap()
        );
        assert_eq!(ip6.ipv6_addr().unwrap(), ip6a);
        assert_eq!(InetAddr::from(IpAddr::V4(ip4a)), ip4);
        assert_eq!(InetAddr::from(IpAddr::V6(ip6a)), ip6);
        assert_eq!(InetAddr::from(ip4a), ip4);
        assert_eq!(InetAddr::from(ip6a), ip6);

        assert_eq!(InetAddr::default(), InetAddr::from_str("0.0.0.0").unwrap());

        #[cfg(feature = "tor")]
        assert_eq!(IpAddr::try_from(ip4).unwrap(), IpAddr::V4(ip4a));
        #[cfg(feature = "tor")]
        assert_eq!(IpAddr::try_from(ip6).unwrap(), IpAddr::V6(ip6a));

        #[cfg(not(feature = "tor"))]
        assert_eq!(IpAddr::from(ip4.clone()), IpAddr::V4(ip4a));
        #[cfg(not(feature = "tor"))]
        assert_eq!(IpAddr::from(ip6.clone()), IpAddr::V6(ip6a));

        assert_eq!(InetAddr::from_str("127.0.0.1").unwrap(), ip4);
        assert_eq!(InetAddr::from_str("::1").unwrap(), ip6);
        assert_eq!(format!("{}", ip4), "127.0.0.1");
        assert_eq!(format!("{}", ip6), "::1");

        assert!(!ip4.is_tor());
        assert!(!ip6.is_tor());
    }

    #[test]
    fn test_transport() {
        assert_eq!(format!("{}", Transport::Tcp), "tcp");
        assert_eq!(format!("{}", Transport::Udp), "udp");
        assert_eq!(format!("{}", Transport::Quic), "quic");
        assert_eq!(format!("{}", Transport::Mtcp), "mtcp");

        assert_eq!(Transport::from_str("tcp").unwrap(), Transport::Tcp);
        assert_eq!(Transport::from_str("Tcp").unwrap(), Transport::Tcp);
        assert_eq!(Transport::from_str("TCP").unwrap(), Transport::Tcp);
        assert_eq!(Transport::from_str("udp").unwrap(), Transport::Udp);
        assert_eq!(Transport::from_str("quic").unwrap(), Transport::Quic);
        assert_eq!(Transport::from_str("mtcp").unwrap(), Transport::Mtcp);
        assert!(Transport::from_str("xtp").is_err());
    }

    #[test]
    fn test_inet_socket_addr() {
        let ip4a = "127.0.0.1".parse().unwrap();
        let ip6a = "::1".parse().unwrap();
        let socket4a = "127.0.0.1:6865".parse().unwrap();
        let socket6a = "[::1]:6865".parse().unwrap();

        let ip4 = InetSocketAddr::socket(ip4a, 6865);
        let ip6 = InetSocketAddr::socket(ip6a, 6865);
        assert_eq!(InetSocketAddr::from(SocketAddr::V4(socket4a)), ip4);
        assert_eq!(InetSocketAddr::from(SocketAddr::V6(socket6a)), ip6);
        assert_eq!(InetSocketAddr::from(socket4a), ip4);
        assert_eq!(InetSocketAddr::from(socket6a), ip6);

        assert_eq!(
            InetSocketAddr::default(),
            InetSocketAddr::from_str("0.0.0.0:0").unwrap()
        );

        #[cfg(feature = "tor")]
        assert_eq!(
            SocketAddr::try_from(ip4).unwrap(),
            SocketAddr::V4(socket4a)
        );
        #[cfg(feature = "tor")]
        assert_eq!(
            SocketAddr::try_from(ip6).unwrap(),
            SocketAddr::V6(socket6a)
        );

        #[cfg(not(feature = "tor"))]
        assert_eq!(SocketAddr::from(ip4.clone()), SocketAddr::V4(socket4a));
        #[cfg(not(feature = "tor"))]
        assert_eq!(SocketAddr::from(ip6.clone()), SocketAddr::V6(socket6a));

        assert_eq!(InetSocketAddr::from_str("127.0.0.1:6865").unwrap(), ip4);
        assert_eq!(InetSocketAddr::from_str("[::1]:6865").unwrap(), ip6);
        assert_eq!(format!("{}", ip4), "127.0.0.1:6865");
        assert_eq!(format!("{}", ip6), "[::1]:6865");

        assert!(!ip4.is_tor());
        assert!(!ip6.is_tor());
    }

    #[test]
    fn test_inet_socket_addr_ext() {
        let ip4a = "127.0.0.1".parse().unwrap();
        let ip6a = "::1".parse().unwrap();

        let ip4 = InetSocketAddrExt::tcp(SocketAddr::new(ip4a, 6865));
        let ip6 = InetSocketAddrExt::udp(ip6a, 6865);

        assert_eq!(
            InetSocketAddrExt::default(),
            InetSocketAddrExt::from_str("tcp://0.0.0.0:0").unwrap()
        );

        #[cfg(feature = "tor")]
        assert_eq!(
            InetSocketAddrExt::from_str("tcp://127.0.0.1:6865").unwrap(),
            ip4
        );
        #[cfg(feature = "tor")]
        assert_eq!(
            InetSocketAddrExt::from_str("udp://[::1]:6865").unwrap(),
            ip6
        );
        assert_eq!(format!("{}", ip4), "tcp://127.0.0.1:6865");
        assert_eq!(format!("{}", ip6), "udp://[::1]:6865");
    }
}
