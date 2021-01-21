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

use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
/// Unknown format string
pub struct FormatParseError;

/// Formats representing generic binary data input or output
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum BinaryFormat {
    /// Raw/binary file with data
    #[display("bin")]
    Bin = 1,

    /// Data encoded as hexadecimal (Base16) string
    #[display("hex")]
    Hex = 2,

    /// Data encoded as Bech32 string starting with `data1` prefix
    #[display("bech32")]
    Bech32 = 3,

    /// Base58 representation
    #[display("base58")]
    Base58 = 4,

    /// Data encoded as Base64 string
    #[display("base64")]
    Base64 = 5,
}

impl FromStr for BinaryFormat {
    type Err = FormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match &s.to_lowercase() {
            s if s.starts_with("bin") => Self::Bin,
            s if s.starts_with("hex") => Self::Hex,
            s if s.starts_with("bech32") => Self::Bech32,
            s if s.starts_with("base64") => Self::Base64,
            _ => Err(FormatParseError)?,
        })
    }
}

/// Formats representing data structures supporting binary encoding and which
/// can be represented by hierarchical data structures, including types
/// supporting LNP/BP strict encoding, bitcoin consensus encoding
/// (`bitcoin::consensus::encode`) or other bitcoin-specific binary encodings
/// (BIP-32 specific encodings, PSBT encoding)
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum StructuredFormat {
    /// Binary representation
    #[display("bin")]
    Bin = 1,

    /// Hexadecimal representation
    #[display("hex")]
    Hex = 2,

    /// Bech32 representation
    #[display("bech32")]
    Bech32 = 3,

    /// Base58 representation
    #[display("base58")]
    Base58 = 4,

    /// Base64 representation
    #[display("base64")]
    Base64 = 5,

    /// JSON
    #[display("json")]
    Json = 10,

    /// YAML
    #[display("yaml")]
    Yaml = 11,

    /// TOML
    #[display("toml")]
    Toml = 12,
}

impl FromStr for StructuredFormat {
    type Err = FormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match &s.to_lowercase() {
            s if s.starts_with("yaml") || s.starts_with("yml") => Self::Yaml,
            s if s.starts_with("json") => Self::Json,
            s if s.starts_with("toml") => Self::Toml,
            s if s.starts_with("bin") => Self::Bin,
            s if s.starts_with("hex") => Self::Hex,
            s if s.starts_with("bech32") => Self::Bech32,
            s if s.starts_with("base64") => Self::Base64,
            _ => Err(FormatParseError)?,
        })
    }
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum FileFormat {
    /// JSON
    #[display("json")]
    Json = 10,

    /// YAML
    #[display("yaml")]
    Yaml = 11,

    /// TOML
    #[display("toml")]
    Toml = 12,

    /// Strict encoding
    #[display("strict-encode")]
    StrictEncode = 0,
}

impl FileFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            FileFormat::Yaml => "yaml",
            FileFormat::Json => "json",
            FileFormat::Toml => "toml",
            FileFormat::StrictEncode => "se",
        }
    }
}

impl FromStr for FileFormat {
    type Err = FormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match &s.to_lowercase() {
            s if s.starts_with("yaml") || s.starts_with("yml") => Self::Yaml,
            s if s.starts_with("json") => Self::Json,
            s if s.starts_with("toml") => Self::Toml,
            s if s.starts_with("se")
                || s.starts_with("dat")
                || s.starts_with("strictencode")
                || s.starts_with("strict-encode")
                || s.starts_with("strict_encode") =>
            {
                Self::StrictEncode
            }
            _ => Err(FormatParseError)?,
        })
    }
}
