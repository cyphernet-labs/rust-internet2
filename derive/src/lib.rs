// LNP/BP Derive Library implementing LNPBP specifications & standards
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
#![cfg_attr(test, deny(warnings))]

#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;
extern crate proc_macro;

#[macro_use]
mod util;

mod api;

use proc_macro::TokenStream;
use syn::DeriveInput;

#[proc_macro_derive(
    Api,
    attributes(
        api,
        bitcoin_encoding_crate,
        strict_encoding_crate,
        lightning_encoding_crate
    )
)]
pub fn derive_api(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    api::inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
