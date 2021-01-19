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

use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "tor")]
use torut::onion::{TorPublicKeyV3, TORV3_PUBLIC_KEY_LENGTH};

use strict_encoding::net::{
    AddrFormat, DecodeError, RawAddr, Transport, Uniform, UniformAddr, ADDR_LEN,
};

use crate::{InetAddr, InetSocketAddr, InetSocketAddrExt};

impl strict_encoding::Strategy for InetAddr {
    type Strategy = strict_encoding::strategies::UsingUniformAddr;
}

impl strict_encoding::Strategy for InetSocketAddr {
    type Strategy = strict_encoding::strategies::UsingUniformAddr;
}

impl strict_encoding::Strategy for InetSocketAddrExt {
    type Strategy = strict_encoding::strategies::UsingUniformAddr;
}

impl Uniform for InetAddr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        match self {
            InetAddr::IPv4(_) => AddrFormat::IpV4,
            InetAddr::IPv6(_) => AddrFormat::IpV6,
            #[cfg(feature = "tor")]
            InetAddr::TorV2(_) => AddrFormat::OnionV2,
            #[cfg(feature = "tor")]
            InetAddr::Tor(_) => AddrFormat::OnionV3,
        }
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        let mut buf = [0u8; ADDR_LEN];
        match self {
            InetAddr::IPv4(ip) => ip.addr(),
            InetAddr::IPv6(ip) => ip.addr(),
            #[cfg(feature = "tor")]
            InetAddr::TorV2(tor) => {
                buf[23..].copy_from_slice(tor.get_raw_bytes().as_ref());
                buf
            }
            #[cfg(feature = "tor")]
            InetAddr::Tor(tor) => {
                buf[1..].copy_from_slice(&tor.to_bytes());
                buf
            }
        }
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        None
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.port.is_some() || addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        Self::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(match addr.addr_format {
            AddrFormat::IpV4 => {
                InetAddr::IPv4(Ipv4Addr::from_uniform_addr_lossy(addr)?)
            }
            AddrFormat::IpV6 => {
                InetAddr::IPv6(Ipv6Addr::from_uniform_addr_lossy(addr)?)
            }
            #[cfg(feature = "tor")]
            AddrFormat::OnionV3 => InetAddr::Tor(tor_from_raw_addr(addr.addr)?),
            _ => Err(DecodeError::UnsupportedAddrFormat)?,
        })
    }
}

impl Uniform for InetSocketAddr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        self.address.addr_format()
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        self.address.addr()
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        Some(self.port)
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        Self::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if let Some(port) = addr.port {
            let address = InetAddr::from_uniform_addr_lossy(addr)?;
            Ok(InetSocketAddr { address, port })
        } else {
            Err(DecodeError::InsufficientData)
        }
    }
}

impl Uniform for InetSocketAddrExt {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        self.1.addr_format()
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        self.1.addr()
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        Some(self.1.port)
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        Some(match self.0 {
            crate::Transport::Tcp => Transport::Tcp,
            crate::Transport::Udp => Transport::Udp,
            crate::Transport::Mtcp => Transport::Mtcp,
            crate::Transport::Quic => Transport::Quic,
        })
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Self::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if let Some(transport) = addr.transport {
            let address = InetSocketAddr::from_uniform_addr_lossy(addr)?;
            let transport = match transport {
                Transport::Tcp => crate::Transport::Tcp,
                Transport::Udp => crate::Transport::Udp,
                Transport::Mtcp => crate::Transport::Mtcp,
                Transport::Quic => crate::Transport::Quic,
            };
            Ok(InetSocketAddrExt(transport, address))
        } else {
            Err(DecodeError::InsufficientData)
        }
    }
}

#[cfg(feature = "tor")]
fn tor_from_raw_addr(raw: RawAddr) -> Result<TorPublicKeyV3, DecodeError> {
    let mut a = [0u8; TORV3_PUBLIC_KEY_LENGTH];
    a.copy_from_slice(&raw[1..]);
    TorPublicKeyV3::from_bytes(&a).map_err(|_| DecodeError::InvalidPubkey)
}
