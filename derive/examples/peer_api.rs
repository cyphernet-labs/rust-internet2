#![allow(dead_code, bare_trait_objects)]

#[macro_use]
extern crate inet2_derive;

#[derive(Clone, Debug, LnpApi)]
#[lnp_api(encoding = "lightning")]
#[non_exhaustive]
pub enum Message {
    #[lnp_api(type = 0x0001)]
    Hello(String),

    /// Some attribute
    #[lnp_api(type = 0x0003)]
    Empty(),

    #[lnp_api(type = 0x0005)]
    NoArgs,

    #[lnp_api(type = 0x0103)]
    AddKeys(Vec<bitcoin::PublicKey>),
}

fn main() {
    use core::convert::TryFrom;
    use internet2::{TypeId, TypedEnum};

    let _ = Message::Empty().get_type();
    Message::try_from_type(
        TypeId::try_from(0x0003).unwrap(),
        &Vec::<u8>::new(),
    )
    .unwrap();
}
