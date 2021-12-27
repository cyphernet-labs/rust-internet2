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

    pub fn payload_size(&self) -> usize {
        let hop_data_len = self.payload.serialized_len();
        let hop_data_bigsize = BigSize::from(hop_data_len);
        hop_data_len + 32
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(LightningEncode, LightningDecode)]
pub struct SphinxPacket<const PACKET_LEN: usize>([u8; PACKET_LEN]);

// TODO: Remove this implementation and do simple derives once strict encoding
//       will merge const generics support
impl<const PACKET_LEN: usize> StrictEncode for SphinxPacket<PACKET_LEN> {
    fn strict_encode<E: Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        e.write_all(&self.0)?;
        Ok(PACKET_LEN)
    }
}

impl<const PACKET_LEN: usize> StrictDecode for SphinxPacket<PACKET_LEN> {
    fn strict_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let mut buf = [0u8; PACKET_LEN];
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
pub struct OnionPacket<const PACKET_LEN: usize> {
    pub version: u8,
    pub point: PublicKey,
    pub hop_payloads: SphinxPacket<PACKET_LEN>,
    pub hmac: Hmac<sha256::Hash>,
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

fn generate_filler_stream<Payload>(
    key: &[u8],
    packet_len: usize,
    hops: &[Hop<Payload>],
    shared_secrets: &[sha256::Hash],
) -> (Vec<u8>, usize)
where
    Payload: SphinxPayload,
{
    let mut filler = vec![0u8; packet_len * 2];
    let iter = hops.iter().take(hops.len() - 1).map(Hop::payload_size);
    let filler_len: usize = iter.clone().sum();

    for (hop_size, secret) in iter.zip(shared_secrets) {
        // Zero-fill the last hop
        filler[packet_len..].fill(0);

        // Generate pseudo-random byte stream
        let stream_key = generate_key(key, secret);
        let stream_bytes = generate_cipher_stream(stream_key, packet_len * 2);

        filler
            .iter_mut()
            .zip(stream_bytes)
            .for_each(|(byte, mask)| *byte ^= mask);

        filler.rotate_left(hop_size);
    }
    (filler, filler_len)
}

fn generate_filler<Payload>(
    key: &[u8],
    packet_len: usize,
    hops: &[Hop<Payload>],
    shared_secrets: &[sha256::Hash],
) -> Vec<u8>
where
    Payload: SphinxPayload,
{
    let (mut filler, filler_len) =
        generate_filler_stream(key, packet_len, hops, shared_secrets);
    filler.resize(packet_len, 0);
    filler.split_off(packet_len - filler_len)
}

impl<const PACKET_LEN: usize> SphinxPacket<PACKET_LEN> {
    /// # Panics
    ///
    /// If serialization length of any of payloads exceeds 1300 - 32 - 3 bytes
    pub fn with<C, Payload>(
        secp: &Secp256k1<C>,
        session_key: SecretKey,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
    ) -> (Self, Hmac<sha256::Hash>)
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let shared_secrets = construct_shared_secrets(secp, hops, session_key);

        // Generate the padding, called "filler strings" in the paper.
        let filler =
            generate_filler(RHO_KEY, PACKET_LEN, hops, &shared_secrets);

        // Allocate and initialize fields to zero-filled slices
        let mut mix_header = [0u8; PACKET_LEN];
        let mut mix_header_len = 0usize;
        let mut next_hmac = Hmac::<sha256::Hash>::default();

        let padding_key = generate_key(PAD_KEY, &session_key[..]);
        let padding_bytes = generate_cipher_stream(padding_key, PACKET_LEN);
        mix_header.copy_from_slice(&padding_bytes);

        let mut last_hop = true;
        for (hop, shared_secret) in hops.iter().zip(shared_secrets).rev() {
            let rho_key = generate_key(RHO_KEY, shared_secret);
            let mu_key = generate_key(MU_KEY, shared_secret);

            // Shift and obduscate routing information
            let stream_bytes = generate_cipher_stream(rho_key, PACKET_LEN);

            let hop_data = hop.payload.serialize();
            let shift_size = hop.payload_size();
            assert!(shift_size <= 1300, "payload is too big");
            mix_header.rotate_right(shift_size);

            let mut writer = Cursor::new(&mut mix_header[..]);
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
            if last_hop {
                mix_header[PACKET_LEN - filler.len()..]
                    .copy_from_slice(&filler);
                last_hop = false;
            }

            let mut engine = HmacEngine::<sha256::Hash>::new(&mu_key);
            engine.input(&mix_header);
            engine.input(assoc_data);
            next_hmac = Hmac::from_engine(engine);
        }

        (SphinxPacket(mix_header), next_hmac)
    }
}

impl<const PACKET_LEN: usize> OnionPacket<PACKET_LEN> {
    /// # Panics
    ///
    /// If serialization length of any of payloads exceeds 1300 - 32 - 3 bytes
    #[cfg(feature = "keygen")]
    pub fn with<C, Payload>(
        secp: &Secp256k1<C>,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
    ) -> Self
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let mut rng = secp256k1::rand::thread_rng();
        let session_key = SecretKey::new(&mut rng);

        OnionPacket::with_session_key(secp, session_key, hops, assoc_data)
    }

    pub fn with_session_key<C, Payload>(
        secp: &Secp256k1<C>,
        session_key: SecretKey,
        hops: &[Hop<Payload>],
        assoc_data: &[u8],
    ) -> Self
    where
        C: Signing,
        Payload: SphinxPayload,
    {
        let (sphinx_packet, hmac) =
            SphinxPacket::with(secp, session_key, hops, assoc_data);

        OnionPacket {
            version: 0,
            point: PublicKey::from_secret_key(secp, &session_key),
            hop_payloads: sphinx_packet,
            hmac,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use amplify::hex::{FromHex, ToHex};

    use super::*;

    const PACKET_LEN: usize = 20 * 65;
    impl SphinxPayload for Vec<u8> {
        fn serialize(&self) -> Vec<u8> {
            self.clone()
        }

        fn serialized_len(&self) -> usize {
            self.len()
        }
    }

    // Tests are written after c-lightning output generated with the following
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

        let hops = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), vec![]),
            Hop::with("0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199".parse().unwrap(), vec![])
        ];

        let shared_secrets =
            construct_shared_secrets(&Secp256k1::new(), &hops, session_key);
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
    fn filler_stream() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();
        let double_hop = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), vec![]),
        ];
        let shared_secrets = construct_shared_secrets(
            &Secp256k1::new(),
            &double_hop,
            session_key,
        );
        let rho_key = generate_key(RHO_KEY, shared_secrets[0]);
        let mut our_filler = generate_cipher_stream(rho_key, PACKET_LEN * 2);
        let (pregenerated_filler, filler_len) = generate_filler_stream(
            RHO_KEY,
            PACKET_LEN,
            &double_hop,
            &shared_secrets,
        );
        our_filler.rotate_left(32);
        assert_eq!(filler_len, 32);
        assert_eq!(pregenerated_filler.to_hex(), our_filler.to_hex());
    }

    #[test]
    fn filler() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let double_hop = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), vec![]),
        ];

        let packet = OnionPacket::<PACKET_LEN>::with_session_key(
            &Secp256k1::new(),
            session_key,
            &double_hop,
            &[],
        );

        let mut our_data = packet.lightning_serialize().unwrap().split_off(34);
        our_data.resize(PACKET_LEN, 0);

        our_data.resize(PACKET_LEN * 2, 0);
        let shared_secrets = construct_shared_secrets(
            &Secp256k1::new(),
            &double_hop,
            session_key,
        );
        let rho_key = generate_key(RHO_KEY, shared_secrets[0]);
        let stream_bytes = generate_cipher_stream(rho_key, PACKET_LEN * 2);
        let filler =
            generate_filler(RHO_KEY, PACKET_LEN, &double_hop, &shared_secrets);
        assert_eq!(
            filler.to_hex(),
            stream_bytes[PACKET_LEN..PACKET_LEN + 32].to_hex()
        );
        let mut our_source: Vec<u8> = our_data
            .iter()
            .zip(&stream_bytes)
            .map(|(b, m)| b ^ m)
            .collect();

        our_source.rotate_left(32);
        assert_eq!(
            our_source[PACKET_LEN - 32..PACKET_LEN].to_hex(),
            filler.to_hex(),
        );
    }

    #[test]
    fn onion_two_empty_hops() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let double_hop = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), vec![]),
        ];

        let packet = OnionPacket::<PACKET_LEN>::with_session_key(
            &Secp256k1::new(),
            session_key,
            &double_hop,
            &[],
        );

        let mut clightning_data = Vec::from_hex(
            "0002629c3b947322792e4f3e30f7f260e404c706b0fcbd32ac105962cc5636f9e1\
            02870aefc85a5a39045cba91e6b540625b98c998ad3b76278d1d2dd9f458688195c\
            40ff8e48df9b2caee33107561a94bff729eb723156680dfedff11605b2d9874865f\
            dd0f1cccf5c75f0fdf5d4ff11458b8eb140cc15161ce3ff82132d4ae425f78262ca\
            270be8e4851c0c82d618e9638e40e9b174e5704859c03855f97f0dc293bd40195d9\
            47ad7400d2e0236d92d05a1f3a617414c893dae3e82a73ec32ae9099d484f4eb716\
            1ab5da18ca2cdc79bca1a8daeb4976d5b4e0a3450a3fc3eb599fcda71c79804f604\
            fd5ac92dda11f5d4151cc8ea91f7dfe00c155e12f962f4364d62158938d0a939e82\
            d463c1c6411ebb452a9c4d1ca859dfac46a4350c2fc2c7fe9bb9baf971ece58f804\
            55c29c15bf896880cdc46dee58c1ee4771a3d7abb1ddf5ec7817b7a0400e51959a0\
            0e9989c2132a8d85fb33b50f2f22ff1914cbca7842aa67324c737b1a1ae45dcac2c\
            4caf501c81d0d70c07772aa7b76f59dd7315c5c537205b02923b86f1bccfd14e93b\
            9778552844792ca4ae25602f948eac78cc5ddf673fdc2243c0f8ff236aa805a95da\
            18230755c8d5e85cee104923cff90b2c183401039acea81fd2bb8446dfb9d1fd9b7\
            915b8cf5317890ef6329fa44fb4a757e829107d60957e595bc29a6d42bd3ec26381\
            e30494b0d247521eae65e42074d626cd2200a60e10fb913ac82da38b81f961ceadb\
            00249a77df6436bce36217a8a3811fce1776151bbdcf6ec327b354211775231abba\
            9f8d45785f4dba750cdfaf711b08c1c9fbe5197c7a773fe65f460802de54339fed3\
            90bf42b239d531cd2534a217ae74b9799c1521c3e6d6f9a9880249056bc9e89d4e1\
            7668cf898b621f964e42b9d6bac390636e3df6f3baf9b986753c3eb7c20eaa2ac61\
            118d36ddf504f0cf065f78cff034fb7547ecbb56b4b3a45e3674bf63bbd83b731e9\
            25012ee31017e071c58d2030c96bebd6ad2934cf40ff774d5b15de95e13a371cc2d\
            080b763b6c243c51da57b5d5f9582fbfecaff33d7665e5dd0a23dfec88a977e078a\
            0ec8d437802a5f273f411fb8ce39736f457e78b889fa77238a1f55cab94ba1a1b41\
            0eda02da4850a9247c35f95940f502ee04520431720a98b64556ad2083d01edc073\
            1f386ab919455ceb81313df480e0f6dd1381ebe7a8936155bbead22afa95289ea5a\
            e2248bda384aa4b4ac0a8b0d5fe2f3e781387fd73c51bfb89ed0d04ff25303f038c\
            5909c01261a4ed1f7013aaa8b0ac53d6d12e08aaa468bdfe61e5fbeab383d381076\
            3f187642322f20e4d81c4fe8470ec49928f54bbfca557e4be48a4e6330d50fc79ce\
            262c337de224d62a475d5cbff0dad6530165d6c09e1648cb8f67637ed4af79df19e\
            410fae4ba195a94482e4cb7a948b03b5a28b7ea9bb9cb7190542f55164aab1d50a5\
            f2c1868722b8d363d1bac43637613132e9ab51602dcb95c2aba5087e17d67dd6fd2\
            09d4a5bf2111cfe2b43af87ef04e53a1b1beec4fd149c8fac42fb9e61b423e231aa\
            468e0a65982ce8dc9767d8534d69e569484a3326270d68b3ae824ee17621eb2fab0\
            5118bdb08f773997f228514a55701b30bc50c1fa8428b3580eb82d5ebf897aa937f\
            10d06ad403f5c76278503930dd81c32270277e8801c249efe1f95c97ddecbbda5aa\
            cea421a9a7fbab536d5573807b0f18f00ad4a7da936f0687abf76154b7e34b51ffc\
            c34074c94bacb8fe44ecd5774ec39baaf7e4769a7a71d8e801636ab79cd85a6c089\
            b53c12fdfd0ccfb4d682f0fff6d8cf97ffbc2c96a4a5dde51fe6f6e43a265f59ff6\
            747d6933ad026957fc5cc4fafbda9570d5cb9be8ec69452d321de4bb7d99c78094b\
            f10f8a292a1858d5c27f93d58ab556a44518966b430b9e0ff5d1f"
        ).unwrap();
        let mut our_data = packet.lightning_serialize().unwrap();
        assert_eq!(clightning_data.to_hex(), our_data.to_hex());

        let mut clightning_data = clightning_data.split_off(34);
        clightning_data.resize(PACKET_LEN, 0);
        let mut our_data = our_data.split_off(34);
        our_data.resize(PACKET_LEN, 0);

        our_data.resize(PACKET_LEN * 2, 0);
        clightning_data.resize(PACKET_LEN * 2, 0);
        let shared_secrets = construct_shared_secrets(
            &Secp256k1::new(),
            &double_hop,
            session_key,
        );
        let rho_key = generate_key(RHO_KEY, shared_secrets[0]);
        let stream_bytes = generate_cipher_stream(rho_key, PACKET_LEN * 2);
        let filler =
            generate_filler(RHO_KEY, PACKET_LEN, &double_hop, &shared_secrets);
        assert_eq!(
            filler.to_hex(),
            stream_bytes[PACKET_LEN..PACKET_LEN + 32].to_hex()
        );
        let mut clightning_source: Vec<u8> = clightning_data
            .iter()
            .zip(&stream_bytes)
            .map(|(b, m)| b ^ m)
            .collect();
        let mut our_source: Vec<u8> = our_data
            .iter()
            .zip(&stream_bytes)
            .map(|(b, m)| b ^ m)
            .collect();

        our_source.rotate_left(32);
        clightning_source.rotate_left(32);
        assert_eq!(
            our_source[..PACKET_LEN].to_hex(),
            clightning_source[..PACKET_LEN].to_hex()
        );
        assert_eq!(
            clightning_source[PACKET_LEN - 32..PACKET_LEN].to_hex(),
            filler.to_hex(),
        );
    }

    #[test]
    fn onion_single_empty_hop() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let single_hop = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
        ];

        let packet = OnionPacket::<PACKET_LEN>::with_session_key(
            &Secp256k1::new(),
            session_key,
            &single_hop,
            &[],
        );

        let clightning_data = Vec::from_hex(
            "0002629c3b947322792e4f3e30f7f260e404c706b0fcbd32ac105962cc5636f9e1\
            023d52a22295b808b3937311f8bdc222dbc3e38ffe0d45efbc2644e01b2e5e17de4\
            59eafaf69320050f420915285f0381181469bfae5287bbb3b6d2f492e68c1612420\
            74c72276ae996233553c90c17beb96b11969b4d35176ae00f27b8fc59bb08536a53\
            50625cad3f908acd160922120732ab472a856be8a202ee96a01b3b619fc8af63ab0\
            f0f77fa5710c2293fe1fb09d09d67d75fc56c7dd16787a6d99ee7e74a77e90568ea\
            e4d6092fadbe2616608891d63cdaee807cb90af6da706ef3388a460348ee2dc0c76\
            e3fc5c6d8f510010c653daf848961c4c9c59548e492d53294fb5b9ea92056f27fb0\
            b837f3a99570a3713c1088765626317426fa6941e07cb70f9e6f25a93865253aa71\
            f0e8e0b9dcbfa17412eab4c6b01373cfa0436f0bc382ef01013482aa0403bec8c07\
            8c12d7184778716956307180e3459e20bf80b30852791f838466db3feee85437ee5\
            aa5f7221ad7c42122867411d96b9036b4dfcaa5304939ce069aed30bc59379c9e14\
            517894499eafdddf2393c8e9f3d173b3e40399f7aa1cdaa9a3df891001bb096e3c8\
            146d65aae6bfc4bb7199eb28dacfda3c633794acfcd14103001434c3c4894a80de0\
            ccc3d02549b17a6edd3f749789ca15b0f5d7d72a6b50216a9c2a2cce2e6d724c91c\
            a746184267730aaa9f4b6809be8a74d72742296dbb609d4bc0128aed016311f42a7\
            dd3a763bfb28d4271ffc98407de7c7c9b883498600f51cfb16697ee73023e8ec06f\
            cdff47e9238189b2a38aaaaafb4bbd8ad67e247f566ed115eaaff5fe2b091e7623d\
            dd2a4614743f44a859946a0a63ef1dce9c61d1e5fe70d8e72591c62c2b667a1d69b\
            f6ade1895d984d4a1fca3ce4b9e99164c07b8a2bd39faf2c57b6f3e8d8541e7224a\
            01944f56f3917be6e57abdec94adc1701ff58f4ea4d31329c337a366a5023480797\
            5857efa3b3a3465e231d0b0b98d4900b1b94757ab5a4d861b121c0beab5fd16ed35\
            cd2ed8b36a1120ebe920a2993837fc5866a9c4615ad945807632cd40c8ecfb72d1a\
            0dabebbb53fcb97691ef30e4170cd9fb2a3957b906ff04bf4cf65a4304d49ca784d\
            c23c66c32d81c61441c09e589e2b59007b5a4c388f1e97dff78f1d28ef3d666f2c1\
            8c4d0014675363cf62e0f9d7729faf55dba99ecff1fac4314ae8b26d408e5ebbe56\
            c78866f5dbc32db7a67c86c966757092b081b6187e2d0f8ae507fead6b69ac31ca3\
            0d3222b08965c024fc7816ef429cf0826f152f244542aa5fd5d3debe4d3731414d5\
            062b9d8985138d4f8956eeb0c2258a6bdbf775f5d735648b538ef918805bbcc05cf\
            fe350a1d92fe8e2652ccdc6e347e83b585e6f69db78bc298ce44f6726e7ce6bb398\
            71a87a454bcbc6bec43f1d33ff87608571e08228ccf9c7d4c6cbe2f533129c0e07c\
            18b441cf7ad0c1dc9121e028d2ac6bc0ccd7d2f333788cb8adaff7e4856157cf875\
            82828ad392da4d619784dc98695ce2bf7f38dcf1575d9207233d8db893ed6c9a18c\
            501cf188a18d2efbd34d2f51528886f1be72242b3eb6eed688d52f872cee5a3f0e0\
            162632f7ec7cb81ac5190ae672e4c26d849e60b59c6b38e66349393f91dddafa6f4\
            83d70430f6eabdcdee5acf2668dfff6f3c24f928645e3ac18d84705df09e63f6f43\
            c4eb49eccd111cb803dadf2c1bdddee0cd43ae925190280bfa7064b87cbb09f139c\
            24269871818bab6d7f5b95cbd3afce30b6895872ceb676cc8f5aebb007f195fc433\
            8e792a974e9537f9c5a4a66d4790caf0c75af989518c8e2d3f224d514dffe3a7b83\
            9a60c6e3b7adb3e42f101da6bf49d0660d6a269799c7ba83b8164c5385b078795b9\
            505fdf4938097baae37cad7ced3351e660ca5c674c26723c185da"
        ).unwrap();

        let shared_secret = construct_shared_secrets(
            &Secp256k1::new(),
            &single_hop,
            session_key,
        )[0];
        let rho_key = generate_key(RHO_KEY, shared_secret);
        let stream_bytes = generate_cipher_stream(rho_key, PACKET_LEN);

        let our_data = packet.lightning_serialize().unwrap();

        let our_source: Vec<u8> = our_data[34..]
            .iter()
            .zip(&stream_bytes)
            .map(|(b, m)| b ^ m)
            .collect();
        let clightning_source: Vec<u8> = clightning_data[34..]
            .iter()
            .zip(&stream_bytes)
            .map(|(b, m)| b ^ m)
            .collect();

        assert_eq!(our_source.to_hex(), clightning_source.to_hex());

        assert_eq!(our_data.to_hex(), clightning_data.to_hex());
    }

    #[test]
    fn onion_three_empty_hops() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let hops = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), vec![]),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), vec![]),
            Hop::with("0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199".parse().unwrap(), vec![])
        ];

        let packet = OnionPacket::<PACKET_LEN>::with_session_key(
            &Secp256k1::new(),
            session_key,
            &hops,
            &[],
        );

        let clightning_data = Vec::from_hex(
            "0002629c3b947322792e4f3e30f7f260e404c706b0fcbd32ac105962cc5636f9e1\
            0262109b86888619335b951db86ec8f4bf2f7b6749ad290cc8cb8fe3ad693dcfa9e\
            bb60c59438671bcc6eb963a4c2cf0441ea342ba2d219673b31cf6d62179f0828ca8\
            1357fe9d24c68d8075407b1834e912f5cef2e46feeb405fc5d7032b4416f0c49871\
            9f39b08692f7752ee866da23df24d26a5942b04cc37854584cddcbe75ccd479e6f4\
            ca1ed0fb639177be145b18e0b94334e305dab2ffb4f44317e45e86894b562fa832c\
            9c3b932828a3fbe1a4cee4d8e0857ba5c78efab354e35f6737d89435036d34d58e7\
            0b1e436f0b4bf2641d0d929268a42e0d08704aa876dc0fe0e64f5ead81481c6654e\
            cb593d4039925a1876580addf4e72f37753cb82647f83b701da52ee9ae44df5f33a\
            5b59c160d2feec5c2b04877582d6c1c10ee84f783f709476119e2e08a53a55ce9ef\
            12c771f8c49c8ea228b0bacd0aeeba300690734579d1406c6f24d02847552b8de0b\
            87180593c43256a38d29070f06e20fdcf239f9f60c85ca4ed71ae927072e503599a\
            b9c6f4bae51ecf222fd943f29c4466ff02e1e080b5fe63a08e14437056c78ccb817\
            ee1f65fa8563603731b009b0ff2764c081f749f89766202ee5580d8610a6572f3e5\
            e765fd5eb6d68c54f405884ba4f26269c6a1eb090164ee8aa9d480135cb1d5a9841\
            16ec39d592002dcaef0390008af68f1f19e584ea17b0494c6bd2f98e27180c3b1bb\
            ca6a552f188b9587c4acc5cbab09d188b2a51ac56793e466c0d1df44b7c25a0d708\
            269e4f3c96fb4b2bc0d588512afa95c53aaf5ebdb41599d068c2ff05e78f7808cb0\
            0bfdc8bd4a482d4eb9ad2409f47869e81bf4b0085d4a6d05c4836d3e43d567dd583\
            a3eea1f18d07c05888fa384a5a95cc61fa17c5399422578643fa74ab94a8a3ce98c\
            0a0b9ea667eb577178b22cb27075e67ad6552b0b338807e95397c22cd81f786b272\
            f8980e8b6c863bbdfac505ade1effe2db4847d0644f36e70f17f3fbcad2f0d2ba76\
            1355a25722b25890e61508f0390f3ad310155925d29ca84860d5f1c9dfed4c59e3c\
            d28d9db649d828d416fbb6afb77ddf339b84b6e6e5a9f2631b20cdc873b32c69a32\
            75667286fd59275dc29b531158ea9bb2fc7f86687ffc9a8b9add1117ab4ffc0aa3e\
            cbc1c14102b25622d71171d6de244c2ceb3260d14c163b9428ced5b29079cac7c48\
            777da17c687e699812d10e89877147a91ba990666f6eff9c766813749e7f51cb741\
            dcb37ff014bed3f0e7c2546232e9ddcc99106268c3d933f8c66e4e0f6237d6f4156\
            73cd133d54218203cb179bb74d60a4bee67d0e7da48da3b7f6088c9fc93789cdbb7\
            8b090904ee29f75e8536c02ab5c8b4d03a1afb554c62e8434e79d43a3ef1c45c37d\
            c25ae23da67f9642b3a13611a591a1ee86cf6aa35e31955450d4b7f94340abdb988\
            e688d5f84fe733d57616936af5aaf2606b80068687de4e19e503b6fac14f8f0efa3\
            995e643b8bf503c8dc683ae83937679510879a9ed978fc270db0c7fae0f113682c9\
            9737c0bd35021a3499dc3932e30a8dc3c567205c4fbdf429153766fbfb97eb7ef15\
            3e7186d0d0abac15a50d41f90849dc1dcce2c248d9c00ccac0d903c852a75369f48\
            c46065170b07ef9fe357ae9973f48006a1b5002657e550f735b3826a9c1d30fde63\
            6d568f05d92f89b3d779c9adc800de1d77a3451901ae0e516ae4b5cadc0791726cf\
            84c44303b653de52624f362913aa720bff114893c318a379a6d99bc29501a1cb3c5\
            72510a92e868553b346239ab81c6b87cb16679ed98257e3cd018096f06998428f06\
            dc91105c3f5960f7e93f680e8b3af63f2371c00d8a1f715374093a5057b8825b8f7\
            0f7376fdc8360c827f070f71858441729787e0d01d42248f05425").unwrap();

        assert_eq!(
            packet.lightning_serialize().unwrap().to_hex(),
            clightning_data.to_hex()
        );
    }

    #[test]
    fn onion_three_hops() {
        let session_key = SecretKey::from_str(
            "07ddd42ccc4e179475aeb031d618dd3bf6815406aa1cfe4e1f712f9ed6b43bf2",
        )
        .unwrap();

        let hops = vec![
            Hop::with("022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59".parse().unwrap(), Vec::from_hex("00000067000001000100000000000003e90000007b000000000000000000000000000000000000000000000000").unwrap()),
            Hop::with("035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d".parse().unwrap(), Vec::from_hex("00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000").unwrap()),
            Hop::with("0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199".parse().unwrap(), Vec::from_hex("00000067000003000100000000000003e800000075000000000000000000000000000000000000000000000000").unwrap())
        ];

        let packet = OnionPacket::<PACKET_LEN>::with_session_key(
            &Secp256k1::new(),
            session_key,
            &hops,
            &[],
        );

        let clightning_data = Vec::from_hex(
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
            ee39143509722b8b1ceab8db5547cb0a13bf684b3595e83190f88").unwrap();

        assert_eq!(
            packet.lightning_serialize().unwrap().to_hex(),
            clightning_data.to_hex()
        );
    }
}
