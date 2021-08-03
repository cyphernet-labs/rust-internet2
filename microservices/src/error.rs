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

use std::fmt::Debug;
use std::hash::Hash;
#[cfg(feature = "_config")]
use std::io;

#[cfg(feature = "_config")]
use internet2::transport;

#[cfg(feature = "node")]
use crate::rpc;

/// Marker trait with all requirements common to LNP/BP service errors
pub trait Error: std::error::Error + Sized {}

/// Error happening during config initiliaztion
#[cfg(feature = "_config")]
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive] // All feature-gated enum types must be non-exhaustive
pub enum ConfigInitError {
    /// I/O error during config file processing:
    /// {0}
    Io(String),

    /// Unable to parse TOML format of the config file:
    /// {0}
    #[cfg(feature = "toml")]
    #[from]
    Toml(toml::ser::Error),
}

#[cfg(feature = "_config")]
impl From<io::Error> for ConfigInitError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Errors which may happen during bootstrap phase of an application or a
/// daemon, with a support for application-specific errors added as a generic
/// parameter and [`BootstrapError:AppLevel`] variant
#[cfg(feature = "_config")]
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive] // All feature-gated enum types must be non-exhaustive
pub enum BootstrapError<AppLevelError>
where
    AppLevelError: Error,
{
    /// Configuration file error:
    /// {0}
    #[cfg(feature = "shell")] // `node` may have no shell, so we feature-gate this
    #[from]
    Config(settings::ConfigError),

    /// Error during initialization of the configuration file:
    /// {0}
    #[from]
    ConfigInit(ConfigInitError),

    /// Attempt to use Tor service while it's not yet supported
    TorNotYetSupported,

    /// General I/O error: {0}
    Io(String),

    /// Command-line argument parse error reported by Clap:
    /// {0}
    #[from]
    ArgParse(String),

    /// ZeroMQ socket error: {0}
    #[cfg(feature = "zmq")]
    #[from]
    Zmq(zmq::Error),

    /// Error reported by multi-thread engine: {0}
    Multithread,

    /// Error connecting to LNP service: {0}
    #[from]
    Transport(transport::Error),

    /// Application-level error: {0}
    #[from]
    AppLevel(AppLevelError),
}

#[cfg(feature = "_config")]
impl<E> From<&str> for BootstrapError<E>
where
    E: Error,
{
    fn from(err: &str) -> Self {
        BootstrapError::ArgParse(err.to_string())
    }
}

#[cfg(feature = "_config")]
impl<E> From<io::Error> for BootstrapError<E>
where
    E: Error,
{
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Errors which may happen during daemon runtime execution within
/// [`TryService`] run loop. Supports application-specific errors, which may be
/// added as a generic parameter and [`RuntimeError:AppLevel`] variant
#[cfg(feature = "node")]
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum RuntimeError<AppLevelError>
where
    AppLevelError: Error,
{
    /// Error with ZMQ socket: {0}
    #[cfg(feature = "zmq")]
    #[from]
    Zmq(zmq::Error),

    /// RPC error during communications with the remote peer: {0}
    #[from]
    Rpc(rpc::Error),

    /// Application-level runtime error: {0}
    #[from]
    AppLevel(AppLevelError),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DataParseError {
    /// Unknown format of the data required to parse
    UnknownFormat,

    /// format of the data is not supported
    NotSupported(String),
}
