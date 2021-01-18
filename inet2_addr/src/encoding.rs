// Internet2 addresses with support for Tor v2, v3
//
// Written in 2019-2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//     Martin Habovstiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::io;
use strict_encoding::{Error, StrictDecode, StrictEncode};

use crate::{InetAddr, InetSocketAddr, InetSocketAddrExt};

/* Inapplicable: can't impl external traits on external types.
   `InetAddr` & `InetSocketAddr` must be used instead

use std::net::{IpAddr, SocketAddr};
use std::convert::TryFrom;

impl StrictEncode for IpAddr {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&InetAddr::from(*self).to_uniform_encoding())?)
    }
}

impl StrictEncode for SocketAddr {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&InetSocketAddr::from(*self).to_uniform_encoding())?)
    }
}

impl StrictDecode for IpAddr {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; InetAddr::UNIFORM_ADDR_LEN];
        d.read_exact(&mut buf)?;
        let res = InetAddr::from_uniform_encoding(&buf)
            .map(IpAddr::try_from)
            .ok_or(Error::DataIntegrityError(s!(
                "InetAddr uniform encoding failure"
            )))?;
        Ok(res.map_err(|_| {
            Error::DataIntegrityError(s!(
                "Found Onion address when IP address was expected"
            ))
        })?)
    }
}

impl StrictDecode for SocketAddr {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; InetSocketAddr::UNIFORM_ADDR_LEN];
        d.read_exact(&mut buf)?;
        let res = InetSocketAddr::from_uniform_encoding(&buf)
            .map(SocketAddr::try_from)
            .ok_or(Error::DataIntegrityError(s!(
                "InetSocketAddr uniform encoding failure"
            )))?;
        Ok(res.map_err(|_| {
            Error::DataIntegrityError(s!(
                "Found Onion address when IP address was expected"
            ))
        })?)
    }
}
*/

impl StrictEncode for InetAddr {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.to_uniform_encoding())?)
    }
}

impl StrictEncode for InetSocketAddr {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.to_uniform_encoding())?)
    }
}

impl StrictEncode for InetSocketAddrExt {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.to_uniform_encoding())?)
    }
}

impl StrictDecode for InetAddr {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::from_uniform_encoding(&buf).ok_or(
            Error::DataIntegrityError(s!("InetAddr uniform encoding failure")),
        )?)
    }
}

impl StrictDecode for InetSocketAddr {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::from_uniform_encoding(&buf).ok_or(
            Error::DataIntegrityError(s!(
                "InetSocketAddr uniform encoding failure"
            )),
        )?)
    }
}

impl StrictDecode for InetSocketAddrExt {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::from_uniform_encoding(&buf).ok_or(
            Error::DataIntegrityError(s!(
                "InetSocketAddrExt uniform encoding failure"
            )),
        )?)
    }
}
