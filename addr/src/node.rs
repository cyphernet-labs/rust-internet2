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

use crate::InetSocketAddr;

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
