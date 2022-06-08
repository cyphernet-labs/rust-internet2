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

//! BOLT-8 related structures and functions covering Lightning network
//! transport layer

pub mod noise;
#[allow(clippy::module_inception)]
mod session;
mod transcoders;

pub use noise::{
    HandshakeError, NoiseDecryptor, NoiseEncryptor, NoiseTranscoder,
};
pub use session::{
    Receiver, RecvMessage, SendMessage, SendRecvMessage, Sender, Session, Split,
};
pub use transcoders::{
    Decrypt, DecryptionError, Encrypt, PlainTranscoder, Transcode,
};
