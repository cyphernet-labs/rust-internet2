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

use std::any::Any;
use std::convert::TryInto;
use std::io;
use std::sync::Arc;

use amplify::AsAny;
use lightning_encoding::{self, LightningDecode, LightningEncode};
use strict_encoding::{self, StrictEncode};

use super::{tlv, EvenOdd, UnknownTypeError};

/// Message type field value
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
    Display, Debug, From
)]
#[display(inner)]
#[wrapper(LowerHex, UpperHex, Octal, FromStr)]
pub struct TypeId(u16);

impl strict_encoding::Strategy for TypeId {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl LightningEncode for TypeId {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        Ok(e.write(&self.0.to_be_bytes())?)
    }
}

impl LightningDecode for TypeId {
    fn lightning_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let mut id = [0u8; 2];
        d.read_exact(&mut id)?;
        Ok(Self(u16::from_be_bytes(id)))
    }
}

impl EvenOdd for TypeId {}

#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct Source(Vec<Arc<dyn Any>>);

pub trait Extract: AsAny {
    fn get_type(&self) -> TypeId;

    fn to_type<T>(&self) -> T
    where
        Self: Sized,
        TypeId: Into<T>,
    {
        self.get_type().into()
    }

    fn try_to_type<T>(&self) -> Result<T, <TypeId as TryInto<T>>::Error>
    where
        Self: Sized,
        TypeId: TryInto<T>,
    {
        self.get_type().try_into()
    }

    fn get_payload(&self) -> Source;

    fn get_tlvs(&self) -> tlv::Stream;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, AsAny)]
#[display("0x{type_id:#04X} {payload:?}")]
pub struct Payload {
    pub type_id: TypeId,
    pub payload: Vec<u8>,
}

impl Extract for Payload {
    fn get_type(&self) -> TypeId { self.type_id }

    fn get_payload(&self) -> Source {
        Source(vec![Arc::new(self.payload.clone())])
    }

    fn get_tlvs(&self) -> tlv::Stream { tlv::Stream::new() }
}

impl StrictEncode for Payload {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(self.type_id.strict_encode(&mut e)? + e.write(&self.payload)?)
    }
}

impl LightningEncode for Payload {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        Ok(self.type_id.lightning_encode(&mut e)? + e.write(&self.payload)?)
    }
}

pub trait TypedEnum
where
    Self: Sized + Clone,
{
    fn try_from_type(
        type_id: TypeId,
        data: &dyn Any,
    ) -> Result<Self, UnknownTypeError>;
    fn get_type(&self) -> TypeId;
    fn get_payload(&self) -> Vec<u8>;
    fn serialize(&self) -> Vec<u8>;
}

impl<T> From<T> for Payload
where
    T: TypedEnum,
{
    fn from(msg: T) -> Self {
        Payload {
            type_id: msg.get_type(),
            payload: msg.get_payload(),
        }
    }
}
