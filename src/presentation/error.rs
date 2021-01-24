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

use crate::transport;

/// Presentation-level LNP error types
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum Error {
    /// I/O error while processing the data: {0}
    #[from]
    #[from(std::io::Error)]
    Io(amplify::IoError),

    /// invalid connection endpoint data
    InvalidEndpoint,

    /// message contains no data
    NoData,

    /// unknown encoder for encoding LNP message
    NoEncoder,

    /// unknown LNP protocol version
    UnknownProtocolVersion,

    /// Error in lightning-encoded data from LNP message
    #[display(inner)]
    #[from]
    LightningEncoding(lightning_encoding::Error),

    /// Error in strict-encoded data from LNP message
    #[display(inner)]
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// Error in consensus-encoded data from LNP message
    #[display(inner)]
    #[from(bitcoin::consensus::encode::Error)]
    ConsensusEncoding,

    /// unknown data type in LNP message
    #[from(UnknownTypeError)]
    UnknownDataType,

    /// invalid value in LNP message
    InvalidValue,

    /// LNP message with unknown even value
    MessageEvenType,

    /// bad length descriptor in LNP message
    BadLengthDescriptor,

    /// wrong order of TLV types inside LNP message
    TlvStreamWrongOrder,

    /// duplicated TLV type item inside LNP message
    TlvStreamDuplicateItem,

    /// found unknown even TLV record type inside LNP message
    TlvRecordEvenType,

    /// invalid length of TLV record inside LNP message
    TlvRecordInvalidLen,

    /// Transport-level LNP error
    #[display(inner)]
    #[from]
    Transport(transport::Error),
}

impl From<Error> for u8 {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidEndpoint => 0x00,
            Error::Io(_) => 0x01,
            Error::NoData => 0x10,
            Error::NoEncoder => 0x11,
            Error::UnknownProtocolVersion => 0x12,
            Error::LightningEncoding(_) => 0x20,
            Error::StrictEncoding(_) => 0x21,
            Error::ConsensusEncoding => 0x22,
            Error::UnknownDataType => 0x23,
            Error::InvalidValue => 0x24,
            Error::MessageEvenType => 0x30,
            Error::BadLengthDescriptor => 0x31,
            Error::TlvStreamWrongOrder => 0x32,
            Error::TlvStreamDuplicateItem => 0x33,
            Error::TlvRecordEvenType => 0x34,
            Error::TlvRecordInvalidLen => 0x35,
            Error::Transport(_) => 0xF0,
        }
    }
}

/// Error representing unknown LNP message type
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(Debug)]
pub struct UnknownTypeError;
