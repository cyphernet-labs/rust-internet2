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

use std::fmt::{self, Display, Formatter};

#[cfg(feature = "keygen")]
use secp256k1::rand::thread_rng;
use secp256k1::{ecdsa, Secp256k1, Signing};

/// Local node private keys
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
pub struct LocalNode {
    private_key: secp256k1::SecretKey,
    public_key: secp256k1::PublicKey,
}

impl LocalNode {
    /// Constructs new set of private key by using random number generator
    #[cfg(feature = "keygen")]
    pub fn new<C: Signing>(secp: &Secp256k1<C>) -> Self {
        let mut rng = thread_rng();
        let private_key = secp256k1::SecretKey::new(&mut rng);
        let public_key =
            secp256k1::PublicKey::from_secret_key(&secp, &private_key);
        Self {
            private_key,
            public_key,
        }
    }

    #[inline]
    pub fn with(
        private_key: secp256k1::SecretKey,
        public_key: secp256k1::PublicKey,
    ) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    #[inline]
    pub fn node_id(&self) -> secp256k1::PublicKey { self.public_key }

    #[inline]
    pub fn private_key(&self) -> secp256k1::SecretKey { self.private_key }

    #[inline]
    pub fn sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        message: &secp256k1::Message,
    ) -> ecdsa::Signature {
        secp.sign_ecdsa(message, &self.private_key)
    }
}

impl Display for LocalNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "LocalNode({:#})", self.node_id())
        } else {
            write!(f, "{}", self.node_id())
        }
    }
}
