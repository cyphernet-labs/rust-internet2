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

use std::fmt::Debug;
use std::io::{Cursor, Read, Write};

use bitcoin_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use lightning_encoding::{BigSize, LightningEncode};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use strict_encoding::{StrictDecode, StrictEncode};

pub const SPHINX_PACKET_LEN: usize = 20 * 65;

const MU_KEY: &[u8] = &[0x6d, 0x75];
const RHO_KEY: &[u8] = &[0x72, 0x68, 0x6f];
const UM_KEY: &[u8] = &[0x75, 0x6d];
const PAD_KEY: &[u8] = &[0x70, 0x61, 0x64];

pub trait SphinxPayload: Debug {
    fn serialize(&self) -> Vec<u8>;
    fn serialized_len(&self) -> usize;
}

#[derive(Debug)]
pub struct Hop<Payload: SphinxPayload> {
    pub pubkey: PublicKey,
    pub payload: Payload,
}

impl<Payload> Hop<Payload>
where
    Payload: SphinxPayload,
{
    #[inline]
    pub fn with(pubkey: PublicKey, payload: Payload) -> Hop<Payload> {
        Hop { pubkey, payload }
    }

    #[inline]
    pub fn payload_size(&self) -> usize {
        self.payload.serialized_len()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(LightningEncode, LightningDecode)]
pub struct SphinxPacket([u8; SPHINX_PACKET_LEN]);

// TODO: Remove this implementation and do simple derives once strict encoding
//       will merge const generics support
impl StrictEncode for SphinxPacket {
    fn strict_encode<E: Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        e.write_all(&self.0)?;
        Ok(SPHINX_PACKET_LEN)
    }
}

impl StrictDecode for SphinxPacket {
    fn strict_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let mut buf = [0u8; SPHINX_PACKET_LEN];
        d.read_exact(&mut buf)?;
        Ok(SphinxPacket(buf))
    }
}

/// NB: A node upon receiving a higher version packet than it implements:
/// - MUST report a route failure to the origin node.
/// - MUST discard the packet.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[derive(LightningEncode, LightningDecode)]
#[derive(StrictEncode, StrictDecode)]
#[display("onion_packet(v{version}, ...)")]
pub struct OnionPacket {
    pub version: u8,
    pub point: PublicKey,
    pub hop_payloads: SphinxPacket,
    pub hmac: Hmac<sha256::Hash>,
}

impl Default for SphinxPacket {
    fn default() -> Self {
        SphinxPacket::new()
    }
}

fn construct_shared_secrets<C, Payload>(
    secp: &Secp256k1<C>,
    hops: &[Hop<Payload>],
    session_key: SecretKey,
) -> Vec<sha256::Hash>
where
    C: Signing,
    Payload: SphinxPayload,
{
    let mut shared_secrets = Vec::<sha256::Hash>::with_capacity(hops.len());
    let mut ephemeral_key = session_key;

    for hop in hops {
        // Perform ECDH
        let shared_secret = SharedSecret::new(&hop.pubkey, &ephemeral_key);
        let shared_secret = sha256::Hash::from_slice(shared_secret.as_ref())
            .expect("ECDH result is not a 32-byte hash");
        shared_secrets.push(shared_secret);

        // Derive ephemeral public key from private key
        let ephemeral_sk = ephemeral_key;
        let ephemeral_pk = PublicKey::from_secret_key(secp, &ephemeral_sk);

        // Compute blinding factor
        let mut engine = sha256::Hash::engine();
        engine.input(&ephemeral_pk.serialize());
        engine.input(&shared_secret);
        let blinding_factor = sha256::Hash::from_engine(engine);

        // Blind ephemeral key for next loop
        ephemeral_key
            .mul_assign(&blinding_factor)
            .expect("negligible probability of exceeding group size");
    }

    shared_secrets
}

fn generate_key(key: &[u8], shared_secret: impl AsRef<[u8]>) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key);
    engine.input(shared_secret.as_ref());
    Hmac::from_engine(engine).into_inner()
}

fn generate_cipher_stream(prng_seed: [u8; 32], len: usize) -> Vec<u8> {
    let mut stream = vec![0u8; len];
    let mut cypher = ChaCha20::new_from_slices(&prng_seed, &[0u8; 12])
        .expect("incorrect ChaCha20 initialization");
    cypher
        .try_apply_keystream(&mut stream)
        .expect("cypher stream implementation diverged from BOLT-4");
    stream
}

fn generate_filler<Payload>(
    key: &[u8],
    filler_len: usize,
    hops: &[Hop<Payload>],
    shared_secrets: &[sha256::Hash],
) -> Vec<u8>
where
    Payload: SphinxPayload,
{
    let mut filler = vec![0u8; filler_len];

    for (hop_size, secret) in
        hops.iter().map(Hop::payload_size).zip(shared_secrets).rev()
    {
        filler.rotate_left(hop_size);
        // Zero-fill the last hop
        filler[filler_len - hop_size..].fill(0);

        // Generate pseudo-random byte stream
        let stream_key = generate_key(key, secret);
        let stream_bytes = generate_cipher_stream(stream_key, filler_len);

        filler
            .iter_mut()
            .zip(stream_bytes)
            .for_each(|(byte, mask)| *byte ^= mask);
    }

    filler
}

impl SphinxPacket {
    pub fn new() -> SphinxPacket {
        // Generate public and secret keys
        todo!("Generate data filled with noise")
    }

    /// # Panics
    ///
    /// If serialization length of any of payloads exceeds 1300 - 32 - 3 bytes
    pub fn with<C, Payload>(
        secp: &Secp256k1<C>,
        session_key: SecretKey,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
        strict_encode: bool,
    ) -> SphinxPacket
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let shared_secrets = construct_shared_secrets(secp, hops, session_key);

        // Generate the padding, called "filler strings" in the paper.
        let filler =
            generate_filler(RHO_KEY, SPHINX_PACKET_LEN, hops, &shared_secrets);

        // Allocate and initialize fields to zero-filled slices
        let mut mix_header = [0u8; SPHINX_PACKET_LEN];
        let mut mix_header_len = 0usize;
        let mut next_hmac = Hmac::<sha256::Hash>::default();

        let padding_key = generate_key(PAD_KEY, &session_key[..]);
        let padding_bytes =
            generate_cipher_stream(padding_key, SPHINX_PACKET_LEN);
        mix_header.copy_from_slice(&padding_bytes);

        let mut first_hop = true;
        for (hop, shared_secret) in hops.iter().zip(shared_secrets).rev() {
            let rho_key = generate_key(RHO_KEY, shared_secret);
            let mu_key = generate_key(MU_KEY, shared_secret);

            // Shift and obduscate routing information
            let stream_bytes =
                generate_cipher_stream(rho_key, SPHINX_PACKET_LEN);

            let hop_data = hop.payload.serialize();
            let hop_data_len = hop_data.len();
            let hop_data_bigsize = BigSize::from(hop_data_len);
            let shift_size = hop_data_len
                + 32
                + if strict_encode {
                    2
                } else {
                    hop_data_bigsize.len()
                };
            assert!(shift_size <= 1300, "payload is too big");
            mix_header.rotate_right(shift_size);

            let mut writer = Cursor::new(&mut mix_header[..]);
            if strict_encode {
                hop_data_len
                    .strict_encode(&mut writer)
                    .expect("memory writer does not error");
            } else {
                hop_data_bigsize
                    .lightning_encode(&mut writer)
                    .expect("memory writer does not error");
            }
            writer
                .write_all(&hop_data)
                .expect("memory writer does not error");
            writer
                .write_all(next_hmac.as_inner())
                .expect("memory writer does not error");
            mix_header_len += shift_size;

            mix_header
                .iter_mut()
                .zip(stream_bytes)
                .for_each(|(byte, mask)| {
                    *byte ^= mask;
                });

            // These need to be overwritten, so every node generates a correct
            // padding
            if first_hop {
                mix_header[mix_header_len..].copy_from_slice(
                    &filler[..SPHINX_PACKET_LEN - mix_header_len],
                );
                first_hop = false;
            }

            let mut engine = HmacEngine::<sha256::Hash>::new(&mu_key);
            engine.input(&mix_header[..mix_header_len]);
            engine.input(assoc_data);
            next_hmac = Hmac::from_engine(engine);
        }

        SphinxPacket(mix_header)
    }

    pub fn hmac(&self, assoc_data: &[u8]) -> Hmac<sha256::Hash> {
        let mut engine = Hmac::<sha256::Hash>::engine();
        engine.input(&self.0);
        engine.input(assoc_data);
        Hmac::from_engine(engine)
    }
}

impl OnionPacket {
    /// # Panics
    ///
    /// If serialization length of any of payloads exceeds 1300 - 32 - 3 bytes
    #[cfg(feature = "keygen")]
    pub fn with<C, Payload>(
        secp: &Secp256k1<C>,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
        strict_encode: bool,
    ) -> OnionPacket
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let mut rng = secp256k1::rand::thread_rng();
        let session_key = SecretKey::new(&mut rng);

        OnionPacket::with_session_key(
            secp,
            session_key,
            hops,
            assoc_data,
            strict_encode,
        )
    }

    pub fn with_session_key<C, Payload>(
        secp: &Secp256k1<C>,
        session_key: SecretKey,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
        strict_encode: bool,
    ) -> OnionPacket
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let sphinx_packet = SphinxPacket::with(
            secp,
            session_key,
            hops,
            assoc_data,
            strict_encode,
        );

        OnionPacket {
            version: 0,
            point: PublicKey::from_secret_key(secp, &session_key),
            hmac: sphinx_packet.hmac(assoc_data),
            hop_payloads: sphinx_packet,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin_hashes::hex::FromHex;

    use super::*;

    impl SphinxPayload for Vec<u8> {
        fn serialize(&self) -> Vec<u8> {
            self.clone()
        }

        fn serialized_len(&self) -> usize {
            self.len()
        }
    }

    fn hops() -> Vec<Hop<Vec<u8>>> {
        vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), Vec::from_hex("00000067000001000100000000000003e90000007b000000000000000000000000000000000000000000000000").unwrap()),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), Vec::from_hex("00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000").unwrap()),
            Hop::with("0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199".parse().unwrap(), Vec::from_hex("00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000").unwrap())
        ]
    }

    // Test is written after c-lightning output generated with the following
    // command: ```
    // lightning-cli createonion '[
    //   {
    //      "pubkey":
    // "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    //      "payload":
    // "00000067000001000100000000000003e90000007b000000000000000000000000000000000000000000000000"
    //   }, {
    //      "pubkey":
    // "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
    //      "payload":
    // "00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000"
    //   }, {
    //      "style": "legacy",
    //      "pubkey":
    // "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
    //      "payload":
    // "00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000"
    //   }
    // ]' "" 07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2
    // ```
    #[test]
    fn shared_secrets() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let shared_secrets =
            construct_shared_secrets(&Secp256k1::new(), &hops(), session_key);
        assert_eq!(shared_secrets.len(), 3);
        assert_eq!(
            shared_secrets[0],
            "f48d45829d50d1af09d9ac9bde5fa21147b396aba605bf8eee8728c5366eeefc"
                .parse()
                .unwrap()
        );
        assert_eq!(
            shared_secrets[1],
            "e51a387a3ae3900e9bf9d9607f0af04dc910a87336205427f1914dcec5061399"
                .parse()
                .unwrap()
        );
        assert_eq!(
            shared_secrets[2],
            "1f1ff5da2f0cf66db49e4b27e279a086e4817bf97e6e75bf3e5d8c4b2493e7da"
                .parse()
                .unwrap()
        );
    }
}
