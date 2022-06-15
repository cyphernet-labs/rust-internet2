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

use secp256k1::{ecdsa, Secp256k1, Signing};

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
#[derive(Debug, Display, Error, From)]
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
    feature = "lightning_encoding",
    derive(LightningEncode, LightningDecode)
)]
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

    /// Returns node public key
    #[inline]
    pub fn public_key(self) -> secp256k1::PublicKey { self.id.public_key() }
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

/// Local node, keeping its id and private key
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{id}")]
pub struct LocalNode {
    id: NodeId,
    private_key: secp256k1::SecretKey,
}

impl LocalNode {
    /// Creates new local node id generating private key with random number
    /// generator
    #[cfg(feature = "keygen")]
    pub fn new<C: Signing>(secp: &Secp256k1<C>) -> Self {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let private_key = secp256k1::SecretKey::new(&mut rng);
        let public_key =
            secp256k1::PublicKey::from_secret_key(secp, &private_key);
        Self {
            private_key,
            id: NodeId::from(public_key),
        }
    }

    /// Constructs local node id from a given node private key.
    #[inline]
    pub fn with<C: Signing>(
        secp: &Secp256k1<C>,
        private_key: secp256k1::SecretKey,
    ) -> Self {
        Self {
            private_key,
            id: secp256k1::PublicKey::from_secret_key(secp, &private_key)
                .into(),
        }
    }

    /// Returns id of this node.
    #[inline]
    pub fn node_id(&self) -> NodeId { self.id }

    /// Returns id of this node.
    #[inline]
    pub fn private_key(&self) -> secp256k1::SecretKey { self.private_key }

    /// Signs the message with the node private key.
    #[inline]
    pub fn sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        message: &secp256k1::Message,
    ) -> ecdsa::Signature {
        secp.sign_ecdsa(message, &self.private_key)
    }
}
