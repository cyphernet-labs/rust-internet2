// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by Rajarshi Maitra
// Refactored in 2022 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
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

use amplify::num::u24;
use amplify::Bipolar;

use super::handshake::HandshakeError;
use super::{chacha, hkdf};
#[cfg(feature = "keygen")]
use crate::session::noise::HandshakeState;
use crate::session::transcoders::{Decrypt, Encrypt, Transcode};
#[cfg(feature = "keygen")]
use crate::{transport, DuplexConnection};

pub type SymmetricKey = [u8; 32];

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum FramingProtocol {
    Brontide = 2,
    Brontozaur = 3,
}

impl From<usize> for FramingProtocol {
    fn from(len: usize) -> Self {
        match len {
            2 => FramingProtocol::Brontide,
            3 => FramingProtocol::Brontozaur,
            _ => unreachable!("invalid Noise_XK protocol ids"),
        }
    }
}

impl FramingProtocol {
    pub const fn message_len_size(self) -> usize {
        match self {
            FramingProtocol::Brontide => 2,
            FramingProtocol::Brontozaur => 3,
        }
    }

    pub const fn header_size(self) -> usize {
        self.message_len_size() + chacha::TAG_SIZE
    }
}

pub const KEY_ROTATION_PERIOD: u32 = 1000;

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
    From
)]
#[display(doc_comments)]
pub enum EncryptionError {
    /// message length {0} exceeds maximum size allowed for the encryption
    /// protocol frame.
    ExceedingMaxLength(usize),

    /// chacha20poly1305 AEAD encrypter error.
    #[from(chacha20poly1305::aead::Error)]
    ChaCha,

    /// message provided for a Noise protocol has incorrect length
    ExpectedMessageLenMismatch,
}

#[derive(Debug)]
// TODO: Switch on enum type for generic (after MSRV bump)
pub struct NoiseEncryptor<const LEN_SIZE: usize> {
    sending_key: SymmetricKey,
    sending_chaining_key: SymmetricKey,
    sending_nonce: u32,
    remote_pubkey: secp256k1::PublicKey,
}

impl<const LEN_SIZE: usize> NoiseEncryptor<LEN_SIZE> {
    pub const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize =
        LEN_SIZE + chacha::TAG_SIZE;
    const MESSAGE_LEN_SIZE: usize = LEN_SIZE;

    pub fn encrypt_buf(
        &mut self,
        buffer: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let length = buffer.len();
        let length_bytes = match FramingProtocol::from(LEN_SIZE) {
            FramingProtocol::Brontide if length > u16::MAX as usize => {
                return Err(EncryptionError::ExceedingMaxLength(length))
            }
            FramingProtocol::Brontozaur if length > u24::MAX.into_usize() => {
                return Err(EncryptionError::ExceedingMaxLength(length))
            }
            FramingProtocol::Brontide => (length as u16).to_be_bytes().to_vec(),
            FramingProtocol::Brontozaur => u24::try_from(length as u32)
                .expect("we just checked length correspondence")
                .to_le_bytes()
                .to_vec(),
        };

        let mut ciphertext = vec![
            0u8;
            Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE
                + length as usize
                + chacha::TAG_SIZE
        ];

        chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            &length_bytes,
            &mut ciphertext[..Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE],
        )?;
        self.increment_nonce();

        let _ = &chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            buffer,
            &mut ciphertext[Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE..],
        )?;
        self.increment_nonce();

        Ok(ciphertext)
    }

    fn increment_nonce(&mut self) {
        NoiseTranscoder::<LEN_SIZE>::increment_nonce(
            &mut self.sending_nonce,
            &mut self.sending_chaining_key,
            &mut self.sending_key,
        );
    }
}

impl<const LEN_SIZE: usize> Encrypt for NoiseEncryptor<LEN_SIZE> {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        match self.encrypt_buf(buffer.borrow()) {
            Ok(values) => values,
            Err(_) => Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct NoiseDecryptor<const LEN_SIZE: usize> {
    receiving_key: SymmetricKey,
    receiving_chaining_key: SymmetricKey,
    receiving_nonce: u32,

    pending_message_length: Option<usize>,
    read_buffer: Option<Vec<u8>>,
    poisoned: bool, /* signal an error has occurred so None is returned on
                     * iteration after failure */
    remote_pubkey: secp256k1::PublicKey,
}

impl<const LEN_SIZE: usize> NoiseDecryptor<LEN_SIZE> {
    pub const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize =
        LEN_SIZE + chacha::TAG_SIZE;
    const MESSAGE_LEN_SIZE: usize = LEN_SIZE;

    pub fn read_buf(&mut self, data: &[u8]) {
        let read_buffer = self.read_buffer.get_or_insert(Vec::new());
        read_buffer.extend_from_slice(data);
    }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, EncryptionError> {
        let mut read_buffer = if let Some(buffer) = self.read_buffer.take() {
            buffer
        } else {
            Vec::new()
        };

        if let Some(data) = new_data {
            read_buffer.extend_from_slice(data);
        }

        let (current_message, offset) = self.decrypt_buf(&read_buffer[..])?;
        read_buffer.drain(..offset); // drain the read buffer
        self.read_buffer = Some(read_buffer); // assign the new value to the built-in buffer
        Ok(current_message)
    }

    fn decrypt_buf(
        &mut self,
        buffer: &[u8],
    ) -> Result<(Option<Vec<u8>>, usize), EncryptionError> {
        let message_length = if let Some(length) = self.pending_message_length {
            // we have already decrypted the header
            length
        } else {
            if buffer.len() < Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE {
                // A message must be at least 18 or 18 bytes (2 or 3 for
                // encrypted length, 16 for the tag)
                return Ok((None, 0));
            }

            let encrypted_length =
                &buffer[0..Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE];

            let mut decrypt =
                |length_bytes: &mut [u8]| -> Result<(), EncryptionError> {
                    chacha::decrypt(
                        &self.receiving_key,
                        self.receiving_nonce as u64,
                        &[0; 0],
                        encrypted_length,
                        length_bytes,
                    )?;
                    self.increment_nonce();
                    Ok(())
                };

            // the message length
            match FramingProtocol::from(LEN_SIZE) {
                FramingProtocol::Brontide => {
                    let mut length_bytes = [0u8; 2];
                    decrypt(&mut length_bytes)?;
                    u16::from_be_bytes(length_bytes) as usize
                }
                FramingProtocol::Brontozaur => {
                    let mut length_bytes = [0u8; 3];
                    decrypt(&mut length_bytes)?;
                    u24::from_le_bytes(length_bytes).as_u32() as usize
                }
            }
        };

        let message_end_index = Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE
            + message_length
            + chacha::TAG_SIZE;

        if buffer.len() < message_end_index {
            self.pending_message_length = Some(message_length);
            return Ok((None, 0));
        }

        self.pending_message_length = None;

        let encrypted_message =
            &buffer[Self::TAGGED_MESSAGE_LENGTH_HEADER_SIZE..message_end_index];
        let mut message = vec![0u8; message_length];

        chacha::decrypt(
            &self.receiving_key,
            self.receiving_nonce as u64,
            &[0; 0],
            encrypted_message,
            &mut message,
        )?;

        self.increment_nonce();

        Ok((Some(message), message_end_index))
    }

    fn increment_nonce(&mut self) {
        NoiseTranscoder::<LEN_SIZE>::increment_nonce(
            &mut self.receiving_nonce,
            &mut self.receiving_chaining_key,
            &mut self.receiving_key,
        );
    }

    // Used in tests to determine whether or not excess bytes entered the
    // conduit without needing to bring up infrastructure to properly encode
    // it
    #[cfg(test)]
    pub fn read_buffer_length(&self) -> usize {
        match &self.read_buffer {
            &Some(ref vec) => vec.len(),
            &None => 0,
        }
    }

    #[inline]
    pub(crate) fn pending_message_len(&self) -> Option<usize> {
        self.pending_message_length
    }

    #[inline]
    pub(crate) fn read_buffer(&self) -> Option<&[u8]> {
        self.read_buffer
            .as_ref()
            .and_then(|buf| self.pending_message_length.map(|len| &buf[..len]))
    }
}

impl<const LEN_SIZE: usize> Iterator for NoiseDecryptor<LEN_SIZE> {
    type Item = Result<Option<Vec<u8>>, EncryptionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }

        match self.decrypt_single_message(None) {
            Ok(Some(result)) => Some(Ok(Some(result))),
            Ok(None) => None,
            Err(e) => {
                self.poisoned = true;
                Some(Err(e))
            }
        }
    }
}

impl<const LEN_SIZE: usize> Decrypt for NoiseDecryptor<LEN_SIZE> {
    type Error = HandshakeError;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.decrypt_single_message(Some(buffer.borrow())) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(HandshakeError::Encryption(e)),
        }
    }
}

/// Returned after a successful handshake to encrypt and decrypt communication
/// with peer nodes. It should not normally be manually instantiated.
/// Automatically handles key rotation.
/// For decryption, it is recommended to call `decrypt_message_stream` for
/// automatic buffering.
#[derive(Debug)]
pub struct NoiseTranscoder<const LEN_SIZE: usize> {
    pub encryptor: NoiseEncryptor<LEN_SIZE>,
    pub decryptor: NoiseDecryptor<LEN_SIZE>,
}

impl<const LEN_SIZE: usize> NoiseTranscoder<LEN_SIZE> {
    #[cfg(feature = "keygen")]
    pub fn new_initiator(
        local_key: secp256k1::SecretKey,
        remote_key: secp256k1::PublicKey,
        connection: &mut impl DuplexConnection,
    ) -> Result<Self, transport::Error> {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let ephemeral_key = secp256k1::SecretKey::new(&mut rng);
        let mut handshake = HandshakeState::new_initiator(
            &local_key,
            &remote_key,
            &ephemeral_key,
        );

        let mut data = vec![];
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let Some(ref act) = act {
                connection.as_sender().send_raw(&*act)?;
                if let HandshakeState::Complete(transcoder) = handshake {
                    break Ok(transcoder);
                }
                data =
                    connection.as_receiver().recv_raw(handshake.data_len())?;
            }
        }
    }

    #[cfg(feature = "keygen")]
    pub fn new_responder(
        local_key: secp256k1::SecretKey,
        connection: &mut impl DuplexConnection,
    ) -> Result<Self, transport::Error> {
        use secp256k1::rand::thread_rng;

        let mut rng = thread_rng();
        let ephemeral_key = secp256k1::SecretKey::new(&mut rng);
        let mut handshake =
            HandshakeState::new_responder(&local_key, &ephemeral_key);

        let mut data =
            connection.as_receiver().recv_raw(handshake.data_len())?;
        loop {
            let (act, h) = handshake.next(&data)?;
            handshake = h;
            if let HandshakeState::Complete(transcoder) = handshake {
                break Ok(transcoder);
            }
            if let Some(act) = act {
                connection.as_sender().send_raw(&*act)?;
                data =
                    connection.as_receiver().recv_raw(handshake.data_len())?;
            }
        }
    }

    /// Instantiate a new Conduit with specified sending and receiving keys
    pub fn with(
        sending_key: SymmetricKey,
        receiving_key: SymmetricKey,
        chaining_key: SymmetricKey,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self {
        NoiseTranscoder {
            encryptor: NoiseEncryptor {
                sending_key,
                sending_chaining_key: chaining_key,
                sending_nonce: 0,
                remote_pubkey,
            },
            decryptor: NoiseDecryptor {
                receiving_key,
                receiving_chaining_key: chaining_key,
                receiving_nonce: 0,
                read_buffer: None,
                pending_message_length: None,
                poisoned: false,
                remote_pubkey,
            },
        }
    }

    pub fn remote_pubkey(&self) -> secp256k1::PublicKey {
        self.encryptor.remote_pubkey
    }

    /// Encrypt data to be sent to peer
    pub fn encrypt_buf(
        &mut self,
        buffer: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.encryptor.encrypt_buf(buffer)
    }

    pub fn read_buf(&mut self, data: &[u8]) { self.decryptor.read_buf(data) }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, EncryptionError> {
        self.decryptor.decrypt_single_message(new_data)
    }

    fn increment_nonce(
        nonce: &mut u32,
        chaining_key: &mut SymmetricKey,
        key: &mut SymmetricKey,
    ) {
        *nonce += 1;
        if *nonce == KEY_ROTATION_PERIOD {
            Self::rotate_key(chaining_key, key);
            *nonce = 0;
        }
    }

    fn rotate_key(chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
        let (new_chaining_key, new_key) = hkdf::derive(chaining_key, key);
        chaining_key.copy_from_slice(&new_chaining_key);
        key.copy_from_slice(&new_key);
    }
}

impl<const LEN_SIZE: usize> Encrypt for NoiseTranscoder<LEN_SIZE> {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        match self.encrypt_buf(buffer.borrow()) {
            Ok(values) => values,
            Err(_) => Vec::new(),
        }
    }
}

impl<const LEN_SIZE: usize> Decrypt for NoiseTranscoder<LEN_SIZE> {
    type Error = HandshakeError;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.decrypt_single_message(Some(buffer.borrow())) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(HandshakeError::Encryption(e)),
        }
    }
}

impl<const LEN_SIZE: usize> Transcode for NoiseTranscoder<LEN_SIZE> {
    type Encryptor = NoiseEncryptor<LEN_SIZE>;
    type Decryptor = NoiseDecryptor<LEN_SIZE>;
}

impl<const LEN_SIZE: usize> Bipolar for NoiseTranscoder<LEN_SIZE> {
    type Left = <Self as Transcode>::Decryptor;
    type Right = <Self as Transcode>::Encryptor;

    fn join(decryptor: Self::Left, encryptor: Self::Right) -> Self {
        Self {
            encryptor,
            decryptor,
        }
    }

    fn split(self) -> (Self::Left, Self::Right) {
        (self.decryptor, self.encryptor)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::hex::FromHex;
    use secp256k1::SECP256K1;

    use super::*;
    use crate::BRONTIDE_MSG_MAX_LEN;

    fn setup_peers() -> (
        NoiseTranscoder<{ FramingProtocol::Brontide.message_len_size() }>,
        NoiseTranscoder<{ FramingProtocol::Brontide.message_len_size() }>,
    ) {
        let chaining_key_vec = Vec::<u8>::from_hex(
            "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01",
        )
        .unwrap();
        let mut chaining_key = [0u8; 32];
        chaining_key.copy_from_slice(&chaining_key_vec);

        let sending_key_vec = Vec::<u8>::from_hex(
            "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9",
        )
        .unwrap();
        let mut sending_key = [0u8; 32];
        sending_key.copy_from_slice(&sending_key_vec);

        let receiving_key_vec = Vec::<u8>::from_hex(
            "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442",
        )
        .unwrap();
        let mut receiving_key = [0u8; 32];
        receiving_key.copy_from_slice(&receiving_key_vec);

        let dummy_pubkey = secp256k1::PublicKey::from_secret_key(
            SECP256K1,
            &secp256k1::ONE_KEY,
        );

        let connected_peer = NoiseTranscoder::with(
            sending_key,
            receiving_key,
            chaining_key,
            dummy_pubkey,
        );
        let remote_peer = NoiseTranscoder::with(
            receiving_key,
            sending_key,
            chaining_key,
            dummy_pubkey,
        );

        (connected_peer, remote_peer)
    }

    #[test]
    fn test_empty_message() {
        let (mut connected_peer, mut remote_peer) = setup_peers();

        let message: Vec<u8> = vec![];
        let encrypted_message = connected_peer.encrypt_buf(&message).unwrap();
        assert_eq!(encrypted_message.len(), 2 + 16 + 16);

        let decrypted_message = remote_peer
            .decrypt_single_message(Some(&encrypted_message))
            .unwrap()
            .unwrap();
        assert_eq!(decrypted_message, Vec::<u8>::new());
    }

    #[test]
    fn test_nonce_chaining() {
        let (mut connected_peer, _remote_peer) = setup_peers();
        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();

        let encrypted_message = connected_peer.encrypt_buf(&message).unwrap();
        assert_eq!(encrypted_message, Vec::<u8>::from_hex("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap());

        // the second time the same message is encrypted, the ciphertext should
        // be different
        let encrypted_message = connected_peer.encrypt_buf(&message).unwrap();
        assert_eq!(encrypted_message, Vec::<u8>::from_hex("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap());
    }

    #[test]
    /// Based on RFC test vectors: https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#message-encryption-tests
    fn test_key_rotation() {
        let (mut connected_peer, _remote_peer) = setup_peers();

        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();
        let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

        for _ in 0..1002 {
            let encrypted_message =
                connected_peer.encrypt_buf(&message).unwrap();
            encrypted_messages.push(encrypted_message);
        }

        assert_eq!(encrypted_messages[500], Vec::<u8>::from_hex("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8").unwrap());
        assert_eq!(encrypted_messages[501], Vec::<u8>::from_hex("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd").unwrap());
        assert_eq!(encrypted_messages[1000], Vec::<u8>::from_hex("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09").unwrap());
        assert_eq!(encrypted_messages[1001], Vec::<u8>::from_hex("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36").unwrap());
    }

    #[test]
    fn test_decryption_buffering() {
        let (mut connected_peer, mut remote_peer) = setup_peers();

        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();
        let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

        for _ in 0..1002 {
            let encrypted_message =
                connected_peer.encrypt_buf(&message).unwrap();
            encrypted_messages.push(encrypted_message);
        }

        for _ in 0..501 {
            // read two messages at once, filling buffer
            let mut current_encrypted_message = encrypted_messages.remove(0);
            let next_encrypted_message = encrypted_messages.remove(0);
            current_encrypted_message
                .extend_from_slice(&next_encrypted_message);
            let decrypted_message = remote_peer
                .decrypt_single_message(Some(&current_encrypted_message))
                .unwrap()
                .unwrap();
            assert_eq!(decrypted_message, message);
        }

        for _ in 0..501 {
            // decrypt messages directly from buffer without adding to it
            let decrypted_message =
                remote_peer.decrypt_single_message(None).unwrap().unwrap();
            assert_eq!(decrypted_message, message);
        }
    }

    // Decryption errors should result in Err
    #[test]
    fn decryption_failure_errors() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();

        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer
                .decrypt_single_message(Some(&encrypted))
                .err()
                .unwrap(),
            chacha20poly1305::aead::Error.into()
        );
    }

    // Test next()::None
    #[test]
    fn decryptor_iterator_empty() {
        let (mut connected_peer, _) = setup_peers();

        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next() -> next()::None
    #[test]
    fn decryptor_iterator_one_item_valid() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();
        connected_peer.read_buf(&encrypted);

        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::err -> next()::None
    #[test]
    fn decryptor_iterator_error() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();
        connected_peer.read_buf(&encrypted);

        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error.into()
        );
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::Some -> next()::err -> next()::None
    #[test]
    fn decryptor_iterator_error_after_success() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();
        connected_peer.read_buf(&encrypted);
        let encrypted = remote_peer.encrypt_buf(&[2]).unwrap();
        connected_peer.read_buf(&encrypted);

        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error.into()
        );
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test that next()::Some -> next()::err -> next()::None
    // Error should poison decryptor
    #[test]
    fn decryptor_iterator_next_after_error_returns_none() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();
        connected_peer.read_buf(&encrypted);
        let encrypted = remote_peer.encrypt_buf(&[2]).unwrap();
        connected_peer.read_buf(&encrypted);
        let encrypted = remote_peer.encrypt_buf(&[3]).unwrap();
        connected_peer.read_buf(&encrypted);

        // Get one valid value
        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        let valid_receiving_key = connected_peer.decryptor.receiving_key;

        // Corrupt the receiving key and ensure we get a failure
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error.into()
        );

        // Restore the receiving key, do a read and ensure None is returned
        // (poisoned)
        connected_peer.decryptor.receiving_key = valid_receiving_key;
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::Some -> next()::err -> read() -> next()::None
    // Error should poison decryptor even after future reads
    #[test]
    fn decryptor_iterator_read_next_after_error_returns_none() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt_buf(&[1]).unwrap();
        connected_peer.read_buf(&encrypted);
        let encrypted = remote_peer.encrypt_buf(&[2]).unwrap();
        connected_peer.read_buf(&encrypted);

        // Get one valid value
        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        let valid_receiving_key = connected_peer.decryptor.receiving_key;

        // Corrupt the receiving key and ensure we get a failure
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error.into()
        );

        // Restore the receiving key, do a read and ensure None is returned
        // (poisoned)
        let encrypted = remote_peer.encrypt_buf(&[3]).unwrap();
        connected_peer.read_buf(&encrypted);
        connected_peer.decryptor.receiving_key = valid_receiving_key;
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    #[test]
    fn max_msg_len_limit_value() {
        assert_eq!(BRONTIDE_MSG_MAX_LEN, 65535);
        assert_eq!(BRONTIDE_MSG_MAX_LEN, ::std::u16::MAX as usize);
    }
}
