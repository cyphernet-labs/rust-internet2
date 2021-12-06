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
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::io;
use std::io::{Read, Write};
use std::sync::Arc;

use amplify::Wrapper;
use lightning_encoding::{self, BigSize, LightningDecode};
use strict_encoding::TlvError;

use super::{Error, EvenOdd, Unmarshall, UnmarshallFn};

pub type UnknownMap = BTreeMap<usize, Box<[u8]>>;

/// TLV type field value
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode
)]
#[display(inner)]
#[wrapper(LowerHex, UpperHex, Octal, FromStr)]
pub struct Type(u64);

/// Unknown TLV record represented by raw bytes
#[derive(
    Wrapper,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Debug,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode
)]
pub struct RawValue(Box<[u8]>);

impl EvenOdd for Type {}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    From,
    StrictEncode,
    StrictDecode
)]
pub struct Stream(#[from] BTreeMap<Type, RawValue>);

impl Stream {
    #[inline]
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn get(&self, type_id: &Type) -> Option<&RawValue> {
        self.0.get(type_id)
    }

    #[inline]
    pub fn insert(&mut self, type_id: Type, value: impl AsRef<[u8]>) -> bool {
        self.0
            .insert(type_id, RawValue::from(Box::from(value.as_ref())))
            .is_none()
    }

    #[inline]
    pub fn contains_key(&self, type_id: &Type) -> bool {
        self.0.contains_key(type_id)
    }

    #[inline]
    pub fn len(&self) -> usize { self.0.len() }

    #[inline]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl lightning_encoding::LightningEncode for Stream {
    fn lightning_encode<E: Write>(
        &self,
        e: E,
    ) -> Result<usize, lightning_encoding::Error> {
        // We ignore empty TLV stream according to the lightning serialization
        // rules
        if self.0.is_empty() {
            return Ok(0);
        }
        self.0.lightning_encode(e)
    }
}

impl lightning_encoding::LightningDecode for Stream {
    fn lightning_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        let mut buf = [0u8; 2];
        // Empty data means empty TLV stream and not an error
        if d.read_exact(&mut buf).is_err() {
            return Ok(Stream::default());
        }
        let count = u16::from_be_bytes(buf);
        let mut set: BTreeMap<Type, RawValue> = bmap! {};
        for _ in 0..count {
            let ty = Type::lightning_decode(&mut d)?;
            if set.contains_key(&ty) {
                return Err(TlvError::Repeated(ty.into_inner() as usize).into());
            }
            if let Some(max) = set.keys().max() {
                if *max > ty {
                    return Err(TlvError::Order {
                        read: ty.into_inner() as usize,
                        max: max.into_inner() as usize,
                    }
                    .into());
                }
            }
            set.insert(ty, RawValue::lightning_decode(&mut d)?);
        }
        Ok(Self(set))
    }
}

pub struct Unmarshaller {
    known_types: BTreeMap<Type, UnmarshallFn<Error>>,
    raw_parser: UnmarshallFn<Error>,
}

impl Unmarshall for Unmarshaller {
    type Data = Stream;
    type Error = Error;

    fn unmarshall(
        &self,
        data: &dyn Borrow<[u8]>,
    ) -> Result<Stream, Self::Error> {
        let mut reader = io::Cursor::new(data.borrow());
        let mut tlv = Stream::new();
        let mut prev_type_id = Type(0);
        loop {
            match BigSize::lightning_decode(&mut reader)
                .map(|big_size| Type(big_size.into_inner()))
            {
                // if zero bytes remain before parsing a type
                // MUST stop parsing the tlv_stream
                Err(lightning_encoding::Error::BigSizeEof) => break Ok(tlv),

                // The following rule is handled by BigSize type:
                // if a type or length is not minimally encoded
                // MUST fail to parse the tlv_stream.
                Err(err) => break Err(err.into()),

                // if decoded types are not monotonically-increasing
                // MUST fail to parse the tlv_stream.
                Ok(type_id) if type_id > prev_type_id => {
                    break Err(Error::TlvStreamWrongOrder)
                }

                // if decoded `type`s are not strictly-increasing
                // (including situations when two or more occurrences of the \
                // same `type` are met)
                // MUST fail to parse the tlv_stream.
                Ok(type_id) if tlv.contains_key(&type_id) => {
                    break Err(Error::TlvStreamDuplicateItem)
                }

                Ok(type_id) => {
                    let rec = if let Some(parser) =
                        self.known_types.get(&type_id)
                    {
                        // if type is known:
                        // MUST decode the next length bytes using the known
                        // encoding for type.
                        // The rest of rules MUST be supported by the parser:
                        // - if length is not exactly equal to that required for
                        //   the known encoding for type MUST fail to parse the
                        //   tlv_stream.
                        // - if variable-length fields within the known encoding
                        //   for type are not minimal MUST fail to parse the
                        //   tlv_stream.
                        parser(&mut reader)?
                    }
                    // otherwise, if type is unknown:
                    // if type is even:
                    // MUST fail to parse the tlv_stream.
                    else if type_id.is_even() {
                        break Err(Error::TlvRecordEvenType);
                    }
                    // otherwise, if type is odd:
                    // MUST discard the next length bytes.
                    else {
                        // Here we are actually not discarding the bytes but
                        // rather store them for an upstream users of the
                        // library which may know the meaning of the bytes
                        (self.raw_parser)(&mut reader)?
                    };
                    tlv.insert(
                        type_id,
                        rec.downcast_ref::<&[u8]>()
                            .ok_or(Error::InvalidValue)?,
                    );
                    prev_type_id = type_id;
                }
            }
        }
    }
}

impl Unmarshaller {
    pub fn new() -> Self {
        Self {
            known_types: BTreeMap::new(),
            raw_parser: Unmarshaller::raw_parser,
        }
    }

    fn raw_parser(
        mut reader: &mut dyn io::Read,
    ) -> Result<Arc<dyn Any>, Error> {
        let len = BigSize::lightning_decode(&mut reader)?.into_inner() as usize;

        // if length exceeds the number of bytes remaining in the message
        // MUST fail to parse the tlv_stream
        // Here we don't known how many bytes are remaining, but we can be
        // sure that this number is below Lightning message size limit, so we
        // check against this conditions to make sure we are not attacked
        // with excessive memory allocation vector. The actual condition from
        // BOLT-2 is checked during `read_exact` call below: if the length
        // exceeds the number of bytes left in the message it will return
        // a error
        if len > crate::LNP_MSG_MAX_LEN {
            return Err(Error::TlvRecordInvalidLen);
        }

        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf[..])
            .map_err(|_| Error::TlvRecordInvalidLen)?;

        let rec = RawValue(Box::from(buf));
        Ok(Arc::new(rec))
    }
}

impl Default for Unmarshaller {
    fn default() -> Self { Unmarshaller::new() }
}
