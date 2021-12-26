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

    #[test]
    fn onion_packet() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let packet = OnionPacket::with_session_key(
            &Secp256k1::new(),
            session_key,
            &hops(),
            &[],
            false,
        );

        assert_eq!(
            packet.lightning_serialize().unwrap(),
            Vec::from_hex(
            "0002629c3b947322792e4f3e30f7f260e404c706b0fcbd32ac105962cc5636f9e1\
            023d52a24595b809b3927311f8bdc222d82ae38ffe7645efbc2644e01b2e5e17de6\
            bd95133fa6872a62e06c5fbaaa3c6fe5c114b6c58f972427f09494f00c2b6fb44c1\
            f9f7b35cd685ac53665c31c26eee6c898a2bcdd9b99e25f121b5bb69da814b4b448\
            65bb6f4403e564f812c9210a7ab8bc78e7966f7a6f791be9a2f01f6fec1babbfe7e\
            a089d6db9a56582dc256d38bf3ac8159ef9cb6373060b07e16003d8f103fd8a396d\
            318d566529ef3653a55fdc760d81d26181ff4ea37e77d4978ab546d1b8d382e58c8\
            850f0da08b4975e72566ed84f7012f08c8294e69560c489ed18380835cf22dc2094\
            e488c49fa467b053e149701148868b88dd7fadbf4f86ae88419b4f98277f5d9b484\
            35b628afbe305bdcc0d65ec3757d0e72bfbfc69ff0621bcff7178b4fd3d61be9d0e\
            321e4602444e83a4265c5e032f8af9c67a273b908fb3eac68a31283dd187a1bd4be\
            113bee45ae304c1646f92a6775d0f56ec5c44c32735d9a43903d8767f7a724828b7\
            118e66910f2aba8bd10d7214b0e3fdfdc224f5230fae8ffe356d5d9054efbecf8d3\
            261b2684b0e24986dc1ccedd978ca43d1be0a9e83ddf390a95142fe8d7c328837fe\
            aa71d716afb6c1840c379f4c80d9c7b76d84ce1addb7f0e1d5b1e637223f7df3a3d\
            6b140cfca1ed7258949efeb65139f9271eb02809f8d6596df7b1d103e1f54818039\
            8a3fda76a89637880b9e8a583dccc5a03ae31e806855a8afeb05503df2aab222c93\
            99533320e9f81884e4fba426ef4452ef3624c789d589314109b46eaf3a4b546b32e\
            80f49e6b4e56567bcbc143e4536d9b0501e584662edcfde8b76344ddb336e08a682\
            3d09252c475cf2683ff1639ee4458c10641a18146967c13bc27a621526f84c7fcdf\
            aa7f248ff2408e4f4db011d9574978c9a9203409705ff2231c89c7e7a31ab73d01e\
            537b0676fc3f7ca0f337c03d6a3ec009d6ef72ddd7f962dac3fbe4fcc864c441e91\
            c06081bda17da456147e158c99a11295e35a1514ba79c473dc63e020091bc0bc2ab\
            a23cdec4b1407c56d0d32064d06aeb42b24c48c4cc67e52db13714630b937ccb96e\
            f235cfd090f734b7e820fe3f970a1eb283ff3ba2dccd0dfcbdb6f5a269da1cbd201\
            718116d0ce0e2241f6989b98956113fe7b380cf20b42d62d4702f14665f172685ef\
            13b0cf763edd868e0b78059146c9e865fd3d0ad273741631473d6920bc85909cdde\
            0eed6fab1849b19ab59ea6a308006ba88885b6d45b497a6df9cf314c441347b4a33\
            8a36c54b05428b5ede0d9e62931a22e2d777bfcdf7b22f77c3590d4ee5a82e058a9\
            2fb716a9e232e0133e947e7bbc1d791e701ae02127f89e92db79d86b7d20f20d2b9\
            346707b09766fb73add8b70ce509f4537cd86b51cce4f01fc5b2ce7cc59c2f1c12a\
            10ff2dc10f638b8c1347d14c4f6966f0348724f5ffa1d96b044de9181312f7a1e80\
            2ee9fc63b6e2f26fa560c2e77058b02a8a74e8501ab0dba8ed3c1192418b66736c7\
            e036f4bd312a6ba912e0cfc056373b2c90b3107f28b82eaf7438168275ee6e76481\
            bda20e15e91bacb749ae4e3c363b443ee78e5227f92d7a14ae3068e41cd1eb53af5\
            f620cbec18b39ab5986e03174b376a6a196f4b979e58992b0d14f5fc9e36707a215\
            120b4dbcb7ca2f76a5c8c77b3af07b1fc8326eee0da292a47264c6768d60003fc33\
            5a014290d41d9f605a00bd4120962d58009429bb41e17c83f6c3d47b704e20e04d8\
            eeaef2ef6d6f9756ce84c7ffe0adc9ac24483e3345f41d1c412cfd64524e2e307b7\
            8b84c03d42fa29ab2855d043b21a922365a23168116bd6b73bde3631f3a273214da\
            ee39143509722b8b1ceab8db5547cb0a13bf684b3595e83190f88").unwrap()
        );
    }
}