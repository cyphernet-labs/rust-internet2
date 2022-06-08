// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Rajarshi Maitra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

mod ceremony;
pub mod chacha;
mod handshake;
mod hkdf;
mod transcoder;

pub use handshake::{HandshakeError, HandshakeState};
pub use transcoder::{
    FramingProtocol, NoiseDecryptor, NoiseEncryptor, NoiseTranscoder,
    KEY_ROTATION_PERIOD,
};
