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

//! Universal internet addresses that support IPv4, IPv6 and Tor

#![recursion_limit = "256"]
// Coding conventions
#![deny(warnings, dead_code, missing_docs)]

#[allow(unused_imports)]
#[macro_use]
extern crate amplify;
#[cfg(feature = "stringly_conversions")]
#[macro_use]
extern crate stringly_conversions_crate as stringly_conversions;
#[cfg(feature = "strict_encoding")]
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "lightning_encoding")]
#[macro_use]
extern crate lightning_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

#[cfg(feature = "strict_encoding")]
mod encoding;
mod inet;
mod node;
mod server;

pub use inet::{
    AddrParseError, InetAddr, InetSocketAddr, InetSocketAddrExt,
    NoOnionSupportError, PartialSocketAddr, Transport,
};
pub use node::{
    LocalNode, NodeAddr, NodeAddrParseError, NodeId, NodeIdInvalidPubkey,
    PartialNodeAddr,
};
pub use server::{
    ServerAddr, ServerAddrParseError, ServiceAddr, ServiceAddrParseError,
};
