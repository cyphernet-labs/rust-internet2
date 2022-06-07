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

use std::str::FromStr;

use crate::inet::PartialSocketAddr;
use crate::{AddrParseError, InetSocketAddr};

/// Node id contains invalid public key
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
    From
)]
#[display(doc_comments)]
#[from(secp256k1::Error)]
pub struct NodeIdInvalidPubkey;

/// Errors parsing [`NodeAddr`] string representation
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum NodeAddrParseError {
    /// invalid public key value representing node id
    #[from(NodeIdInvalidPubkey)]
    InvalidId,

    /// Node address parse error
    #[from]
    #[display(inner)]
    InvalidAddr(AddrParseError),
}

/// Internet P2P node id, represented by a public key of the node.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display(inner)]
pub struct NodeId(secp256k1::PublicKey);

impl NodeId {
    /// Returns public key for this node id.
    #[inline]
    pub fn public_key(self) -> secp256k1::PublicKey { self.0 }
}

impl FromStr for NodeId {
    type Err = NodeIdInvalidPubkey;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(NodeId(s.parse()?)) }
}

/// Internet P2P node address.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("{id}@{addr}")]
pub struct NodeAddr {
    /// P2P node id (node public key).
    pub id: NodeId,
    /// Internet address of the node
    pub addr: InetSocketAddr,
}

impl NodeAddr {
    /// Constructs new node address.
    #[inline]
    pub fn new(id: NodeId, addr: InetSocketAddr) -> NodeAddr {
        NodeAddr { id, addr }
    }
}

impl FromStr for NodeAddr {
    type Err = NodeAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(id), Some(addr), None) => Ok(NodeAddr {
                id: id.parse()?,
                addr: addr.parse()?,
            }),
            _ => Err(AddrParseError::WrongAddrFormat(s.to_owned()).into()),
        }
    }
}

/// Internet P2P node address which may omit port number.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("{id}@{addr}")]
pub struct PartialNodeAddr {
    /// P2P node id (node public key).
    pub id: NodeId,
    /// Internet address of the node, with optional port part.
    pub addr: PartialSocketAddr,
}

impl PartialNodeAddr {
    /// Constructs new node address.
    #[inline]
    pub fn new(id: NodeId, addr: PartialSocketAddr) -> PartialNodeAddr {
        PartialNodeAddr { id, addr }
    }

    /// Converts to [`NodeAddr`] using default port information.
    #[inline]
    pub fn node_addr(self, default_port: u16) -> NodeAddr {
        NodeAddr {
            id: self.id,
            addr: self.addr.inet_socket(default_port),
        }
    }
}

impl FromStr for PartialNodeAddr {
    type Err = NodeAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(id), Some(addr), None) => Ok(PartialNodeAddr {
                id: id.parse()?,
                addr: addr.parse()?,
            }),
            _ => Err(AddrParseError::WrongAddrFormat(s.to_owned()).into()),
        }
    }
}
