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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

#[cfg(feature = "derive")]
pub extern crate strict_encoding_derive as derive;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;

mod core;

pub use crate::core::{
    strategies, strict_deserialize, strict_serialize, Error, Strategy,
    StrictDecode, StrictEncode,
};
