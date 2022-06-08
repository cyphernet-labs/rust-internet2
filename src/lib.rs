// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    warnings,
    //dead_code,
    //missing_docs
)]
#![allow(unused_variables, dead_code)]
#![allow(clippy::needless_borrow)] // Caused by a bug in amplify_derive::Display
                                   // TODO: when we will be ready for the release #![deny(missing_docs, dead_code)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

extern crate chacha20poly1305;
#[cfg(feature = "url")]
extern crate url_crate as url;

#[cfg(feature = "serde")]
extern crate serde_crate as serde;

#[cfg(feature = "derive")]
pub extern crate inet2_derive as derive;

pub extern crate inet2_addr as addr;

#[cfg(feature = "derive")]
pub use inet2_derive::Api;

pub mod presentation;
pub mod session;
pub mod transport;

pub use presentation::{
    sphinx, tlv, CreateUnmarshaller, Payload, TypeId, TypedEnum,
    UnknownTypeError, Unmarshall, UnmarshallFn, Unmarshaller,
};
pub use session::{
    Decrypt, Encrypt, NoiseDecryptor, NoiseEncryptor, NoiseTranscoder,
    PlainTranscoder, SendRecvMessage, Split, Transcode,
};
#[cfg(feature = "zmq")]
pub use transport::zeromq;
#[cfg(feature = "zmq")]
pub use transport::ZmqType;
pub use transport::{unencrypted, Duplex, RoutedFrame};

/// Maximum message (packet payload) length for Brontide protocol
pub const BRONTIDE_MSG_MAX_LEN: usize = u16::MAX as usize;
/// Maximum message (packet payload) length for Brontozaur protocol
pub const BRONTOZAUR_MSG_MAX_LEN: usize = 0xFFFFFF;

/// Trait used by different address types (transport-, session- and
/// presentation-based) for getting scheme part of the URL
pub trait UrlString {
    /// Returns full URL scheme string (i.e. including `:` or `://` parts)
    /// corresponding to the provided address
    fn url_scheme(&self) -> &'static str;

    /// Returns URL string representation for a given node or socket address. If
    /// you need full URL address, please use `Url::from()` instead (this
    /// will require `url` feature for LNP/BP Core Library).
    fn to_url_string(&self) -> String;
}
