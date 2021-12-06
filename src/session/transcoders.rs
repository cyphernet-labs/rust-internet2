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

use std::borrow::Borrow;

use amplify::Bipolar;

use crate::transport::{
    Error, FRAME_PREFIX_SIZE, FRAME_SUFFIX_SIZE, MAX_FRAME_SIZE,
};

pub trait Encrypt {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8>;
}

pub trait Decrypt {
    type Error: ::std::error::Error;

    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub trait Transcode: Bipolar + Encrypt + Decrypt {
    type Encryptor: Encrypt;
    type Decryptor: Decrypt;
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(Debug)]
pub struct DecryptionError;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
pub struct PlainTranscoder;

impl Encrypt for PlainTranscoder {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        let mut data = vec![];
        let buffer = buffer.borrow().to_vec();
        // TODO: (v0.2) check for length value to fit u16
        let len = buffer.len() as u16;
        data.extend(&len.to_be_bytes());
        data.extend(&[0u8; FRAME_PREFIX_SIZE - 2]);
        data.extend(buffer);
        data.extend(&[0u8; FRAME_SUFFIX_SIZE]);
        data
    }
}

impl Decrypt for PlainTranscoder {
    type Error = Error;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let buffer = buffer.borrow();
        let frame_len = buffer.len();
        if frame_len < FRAME_PREFIX_SIZE + FRAME_SUFFIX_SIZE {
            return Err(Error::FrameTooSmall(frame_len));
        }
        if frame_len > MAX_FRAME_SIZE {
            return Err(Error::OversizedFrame(frame_len));
        }
        let mut len_buf = [0u8; 2];
        len_buf.copy_from_slice(&buffer[0..2]);
        let data_len = u16::from_be_bytes(len_buf);
        let len = frame_len - FRAME_SUFFIX_SIZE;
        if data_len != (len - FRAME_PREFIX_SIZE) as u16 {
            return Err(Error::InvalidLength);
        }
        Ok(buffer[FRAME_PREFIX_SIZE..len].to_vec())
    }
}

impl Transcode for PlainTranscoder {
    type Encryptor = Self;
    type Decryptor = Self;
}

impl Bipolar for PlainTranscoder {
    type Left = <Self as Transcode>::Encryptor;
    type Right = <Self as Transcode>::Decryptor;

    fn join(encryptor: Self::Left, _decryptor: Self::Right) -> Self {
        encryptor as PlainTranscoder
    }

    fn split(self) -> (Self::Left, Self::Right) { (self.clone(), self) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_encryption() {
        let transcoder = PlainTranscoder;
        let (mut encoder, mut decoder) = transcoder.split();
        let frame = encoder.encrypt([]);
        assert_eq!(frame, vec![0u8; FRAME_PREFIX_SIZE + FRAME_SUFFIX_SIZE]);
        let data = decoder.decrypt(frame).unwrap();
        assert_eq!(data, Vec::<u8>::new());

        let data = b"Some message";
        let frame = encoder.encrypt(*data);
        assert_eq!(frame, vec![
            0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 111,
            109, 101, 32, 109, 101, 115, 115, 97, 103, 101, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        let decrypted = decoder.decrypt(frame.as_ref()).unwrap();
        assert_eq!(decrypted, data);

        assert_eq!(
            decoder.decrypt(&frame[2..]).unwrap_err(),
            Error::InvalidLength
        );
    }
}
