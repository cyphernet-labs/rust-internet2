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

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "node")]
pub mod server;

use std::fmt::{Debug, Display};
use std::hash::Hash;

use internet2::{presentation, transport};

#[cfg(feature = "node")]
use crate::error::RuntimeError;

/// Marker traits for endpoint identifiers lists
pub trait EndpointId: Copy + Eq + Hash + Display {}

/// Information about server-side failure returned through RPC API
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[display("Server returned failure #{code}: {info})", alt = "#{code}: {info}")]
pub struct Failure {
    /// Failure #{}
    pub code: u16,

    /// Detailed information about the failure
    pub info: String,
}

/// Errors happening with RPC APIs
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// unexpected server response
    UnexpectedServerResponse,

    /// Server failure
    #[from]
    #[display(inner)]
    ServerFailure(Failure),

    /// message serialization or structure error: {0}
    #[from(lightning_encoding::Error)]
    Presentation(presentation::Error),

    /// transport-level protocol error: {0}
    #[from]
    Transport(transport::Error),

    /// provided RPC endpoint {0} is unknown
    UnknownEndpoint(String),
}

impl From<zmq::Error> for Error {
    fn from(err: zmq::Error) -> Self {
        Error::Transport(transport::Error::from(err))
    }
}

impl From<presentation::Error> for Error {
    fn from(err: presentation::Error) -> Self {
        match err {
            presentation::Error::Transport(err) => err.into(),
            err => Error::Presentation(err),
        }
    }
}

impl From<presentation::Error> for Failure {
    fn from(err: presentation::Error) -> Self {
        Failure {
            info: err.to_string(),
            code: u8::from(err) as u16,
        }
    }
}

#[cfg(feature = "node")]
impl<E> From<RuntimeError<E>> for Failure
where
    E: crate::error::Error,
{
    fn from(err: RuntimeError<E>) -> Self {
        Failure {
            code: 100,
            info: err.to_string(),
        }
    }
}

/*
impl From<payment::channel::NegotiationError> for Failure {
    fn from(err: payment::channel::NegotiationError) -> Self {
        Failure {
            code: 1000, // Error from LN
            info: err.to_string(),
        }
    }
}
*/
