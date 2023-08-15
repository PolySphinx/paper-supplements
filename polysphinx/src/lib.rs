//! This module implements the PolySphinx format, as described in "PolySphinx - Extending the
//! Sphinx Mix Format with better Multicast Support".
//!
//! PolySphinx builds on top of the Sphinx format \[1\] and extends it with capabilities to
//! let a mix node generate ciphertext copies that are indistinguishable from each other.
//!
//! The main functionality of this crate is implemented in the [`PolySphinx`] struct.
//!
//! \[1\]: Sphinx: A Compact and Provably Secure Mix Format - George Danezis, Ian Goldberg
use std::{
    cmp::{max, Ordering},
    io::Read,
    iter,
    marker::PhantomData,
    mem,
    ops::Mul,
};

use bitvec::{field::BitField, order::Msb0, slice::BitSlice, vec::BitVec};
use curve25519_dalek::{
    constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
};
use hmac::{Hmac, Mac};
use itertools::chain;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, Rng,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{digest::FixedOutput, Digest, Sha256};
use thiserror::Error;

pub mod node;
use node::Command;
pub mod poly;
pub use poly::{BitPackable, Polyfication};
pub mod tree;
pub use tree::Tree;

/// A trait that ensures that data can be packed in a fixed amount of bits.
///
/// This is used to serialize/deserialize header fields into the PolySphinx packet.
pub trait FixedSizePackable: BitPackable + Copy {
    /// Size of the packed element in bits.
    const SIZE: u32;
}

impl BitPackable for () {
    fn pack(&self) -> Bits {
        Bits::EMPTY
    }

    fn unpack(_: &BitsSlice) -> Result<Self> {
        Ok(())
    }
}

impl FixedSizePackable for () {
    const SIZE: u32 = 0;
}

/// Main error type for fallible PolySphinx operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Error for when the given path is too long.
    #[error("The given path is too long")]
    PathTooLong,

    /// Error for when the (header) payload that should be embedded exceeds the limit.
    #[error("The given payload exceeds the size limit")]
    PayloadTooLarge,

    /// The header has a weird size and its level could not be determined.
    #[error("Could not determine the level of the header")]
    UnknownLevel,

    /// The header MAC does not match.
    #[error("The MAC does not match!")]
    MacMismatch,

    /// An invalid flag byte has been given.
    #[error("Invalid header flag")]
    InvalidFlag,

    /// The given path is not uniform.
    #[error("The given path is non-uniform")]
    NonUniformPath,

    /// An error occurred while packing/unpacking a header value.
    ///
    /// See the error's cause for more information.
    #[error("Error while (un)packing")]
    PackingError(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// An error outside of PolySphinx occurred.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Result type with the error defaulting to [`enum@Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The type to represent elements in G.
pub type GroupElement = MontgomeryPoint;

/// The type to represent public keys.
pub type PublicKey = GroupElement;

/// The type to represent private keys.
pub type PrivateKey = Scalar;

/// The output of the hash functions.
type Hash = [u8; 16];

/// The identifier of mix nodes.
///
/// This is the default from the Sphinx paper, but can be replaced by users to choose more
/// practical types (such as `std::net::Ipv6Addr`).
pub type Identifier = [u8; 16];

impl BitPackable for Identifier {
    fn pack(&self) -> Bits {
        Bits::from_slice(self)
    }

    fn unpack(input: &BitsSlice) -> Result<Self> {
        let mut result = Self::default();
        let mut vec = input.to_bitvec();
        vec.force_align();
        vec.as_raw_slice().read_exact(&mut result).unwrap();
        Ok(result)
    }
}

impl FixedSizePackable for Identifier {
    const SIZE: u32 = 16 * 8;
}

/// A bit-vector suitable for working with our headers.
///
/// Since headers need bitwise manipulation, it is easier to use a wrapper type such as BitVec to
/// deal with the nitty-gritty bit-twiddleing details. The MSB order is chosen to match the
/// notation from \[DG09\], and keeping the storage as `u8` allows for easy usage in the hash
/// functions.
pub type Bits = BitVec<u8, Msb0>;

/// An immutable view into a [`Bits`] vector.
pub type BitsSlice = BitSlice<u8, Msb0>;

/// Type for "destination addresses", as proposed by the original Sphinx paper.
///
/// Note that this can be replaced by more practical types, as long as they are
/// `FixedSizePackable`.
pub type DestinationAddress = [u8; 48];

impl BitPackable for DestinationAddress {
    fn pack(&self) -> Bits {
        Bits::from_slice(self)
    }

    fn unpack(input: &BitsSlice) -> Result<Self> {
        let mut result = [0; 48];
        let mut vec = input.to_bitvec();
        vec.force_align();
        vec.as_raw_slice().read_exact(&mut result).unwrap();
        Ok(result)
    }
}

impl FixedSizePackable for DestinationAddress {
    const SIZE: u32 = 48 * 8;
}

const KAPPA: usize = mem::size_of::<Hash>() * 8;

fn truncate(input: &[u8]) -> Hash {
    let mut hash: Hash = Default::default();
    for (slot, elem) in hash.iter_mut().zip(input.iter()) {
        *slot = *elem;
    }
    hash
}

fn digest_with_salt(elem: &GroupElement, salt: u8) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([salt]);
    hasher.update(elem.0);
    let digest: [u8; 32] = hasher.finalize_fixed().into();
    truncate(&digest)
}

/// A flag signalling the node how the message should be relayed.
#[derive(
    Copy, Clone, Debug, Hash, PartialEq, Eq, FromPrimitive, ToPrimitive, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum HeaderFlag {
    /// Signal the node that the message should be relayed.
    Relay = 0xF1,
    /// Signal the node that the message has reached its destination.
    Destination = 0xF2,
    /// Signal the node that the message should be multicasted.
    Multicast = 0xF3,
}

impl HeaderFlag {
    /// Convert the flag to a bit representation
    pub fn to_bits(self) -> Bits {
        Bits::from_element(self as u8)
    }

    /// Convert the bit representation to the header flag.
    pub fn from_bits(bits: &BitsSlice) -> Option<Self> {
        HeaderFlag::from_u8(bits.load())
    }
}

/// A struct representing a header PolySphinx header.
///
/// Note that you should treat this as an opaque struct. Use the [`Serialize`] and [`Deserialize`]
/// implementations to pass it over the wire, and use [`PolySphinx::unwrap_header`] to consume it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Header {
    /// Sphinx group element.
    ///
    /// This is a pre-computed Diffie-Hellman key exchange, which can be used together with a mix
    /// node's private key to generate a shared secret.
    pub alpha: GroupElement,
    /// (Encrypted) routing information.
    ///
    /// The exact meaning of this depends on the node's job.
    pub beta: Bits,
    /// Message authentication code.
    pub gamma: Hash,
}

impl Header {
    /// Pack a header into a compact bit representation.
    ///
    /// Note that for normal operations, using the [`Serialize`] implementation is preferable.
    pub fn pack(&self) -> Bits {
        let mut packed = Bits::from_slice(&self.alpha.0);
        packed.extend_from_raw_slice(&self.gamma);
        packed.extend_from_bitslice(&self.beta);
        packed
    }

    /// Unpack a header from its compact bit representation.
    pub fn unpack(bits: &BitsSlice) -> Header {
        let mut bits = bits.to_bitvec();
        bits.force_align();
        let mut alpha = [0; 32];
        (&bits.as_raw_slice()[0..32])
            .read_exact(&mut alpha)
            .unwrap();
        let mut gamma = [0; 16];
        (&bits.as_raw_slice()[32..48])
            .read_exact(&mut gamma)
            .unwrap();
        Header {
            alpha: MontgomeryPoint(alpha),
            beta: bits[48 * 8..].to_bitvec(),
            gamma,
        }
    }

    /// Truncate the header's beta value to the given length.
    pub fn truncate_beta(&mut self, length: u32) {
        self.beta.truncate(length as usize);
        self.beta.force_align();
    }

    /// Extend this header's beta value to the given length.
    ///
    /// To extend the header, a PRNG seeded with the given hash is used.
    pub fn extend_beta(&mut self, length: u32, hash: &Hash) {
        let mut rng_seed = <ChaCha20Rng as SeedableRng>::Seed::default();
        (hash as &[u8]).read_exact(&mut rng_seed[..16]).unwrap();

        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        while self.beta.len() < length as usize {
            self.beta.push(rng.gen());
        }
        self.beta.force_align();
    }
}

/// A path through a series of mix nodes.
///
/// For the direct part, a path carries three types of values:
///
/// * The address of the mix node, represented by `A`.
/// * The public key of the mix node, represented by [`PublicKey`].
/// * A value of your choosing to pass along to the hop, for example to carry delay information for
///   stop-and-go mixing. This is represented by type `H`.
/// * Some information for the final node along the path, represented by `F`. This can be the
///   recipient's address, for example.
pub type Path<A = Identifier, H = (), F = ()> = Tree<((A, PublicKey), H), F>;

/// A structure to hold Sphinx parameters.
///
/// The methods on this object allow you to perform Sphinx operations such as creating headers.
///
/// Note that for proper usage, the parameters must match when encrypting/decrypting a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolySphinx<P, A, H, F> {
    /// The maximum amount of hops a message can take.
    max_hops: u32,
    /// The multicast factor.
    multicast_factor: u32,
    /// The updatable encryption scheme
    polyfier: P,
    phantom: PhantomData<(A, H, F)>,
}

impl<A: FixedSizePackable, H: FixedSizePackable, F: FixedSizePackable>
    PolySphinx<poly::Symmetric, A, H, F>
{
    /// Create a new PolySphinx instance with the given maximum hops (per level) and the given
    /// multicast factor.
    pub fn new(max_hops: u32, multicast_factor: u32) -> Self {
        Self::generic_new(max_hops, multicast_factor, poly::Symmetric)
    }
}

impl<P: Polyfication, A: FixedSizePackable, H: FixedSizePackable, F: FixedSizePackable>
    PolySphinx<P, A, H, F>
{
    /// Create a new PolySphinx instance.
    fn generic_new(max_hops: u32, multicast_factor: u32, polyfier: P) -> PolySphinx<P, A, H, F> {
        PolySphinx {
            max_hops,
            multicast_factor,
            polyfier,
            phantom: PhantomData,
        }
    }

    /// The maximum number of hops a message may take per level.
    pub fn max_hops(&self) -> u32 {
        self.max_hops
    }

    /// The multicast factor.
    pub fn multicast_factor(&self) -> u32 {
        self.multicast_factor
    }

    /// The implementation of updatable encryption.
    pub fn polyfier(&self) -> &P {
        &self.polyfier
    }

    /// Prepare the given payload.
    ///
    /// This has to be done by the sender before sending the packet. It uses the initial key
    /// generated by [`PolySphinx::create_polyheader`].
    ///
    /// Note that this function does not add any padding to the payload! Make sure your payloads
    /// are well-padded before you use this.
    pub fn prepare_payload<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &P::EncryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.polyfier.encrypt(rng, key, data)
    }

    /// Recrypt the given payload.
    ///
    /// This is the step done by the mix node to provide bitwise unlinkability.
    pub fn recrypt_payload<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &P::Token,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.polyfier.recrypt(rng, key, data)
    }

    /// Decrypt the given payload.
    pub fn decrypt_payload<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &P::DecryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.polyfier.decrypt(rng, key, data)
    }

    /// The hash function to key the mac, $h_\mu$.
    fn hash_mac(&self, x: &GroupElement) -> Hash {
        digest_with_salt(x, 0xF0)
    }

    /// The hash function to key the PRNG, $h_\rho$.
    fn hash_prng(&self, x: &GroupElement) -> Hash {
        digest_with_salt(x, 0xF1)
    }

    /// The function to generate blinding factors, $h_b$.
    fn blinding_factor(&self, a: &GroupElement, b: &GroupElement) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(a.0);
        hasher.update(b.0);
        Scalar::from_bytes_mod_order(hasher.finalize_fixed().into())
    }

    /// The PRNG used as a stream cipher to encrypt the header.
    ///
    /// This is defined as $\rho$ in \[DG09\].
    fn prng<I>(&self, seed: &Hash) -> impl Iterator<Item = I>
    where
        Standard: Distribution<I>,
    {
        let mut seed = seed as &[u8];
        let mut rng_seed = <ChaCha20Rng as SeedableRng>::Seed::default();
        seed.read_exact(&mut rng_seed[..16]).unwrap();

        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        iter::from_fn(move || Some(rng.gen()))
    }

    /// Encrypt the given bits by `xor`ing them with randomly generated bits.
    ///
    /// Internally, this uses [`PolySphinx::hash_prng`] to convert the key to a proper PRNG seed
    /// and then [`PolySphinx::prng`] to generate cryptographically secure random bits.
    ///
    /// The `skip` parameter tells us how many bits from the start of the PRNG output we want to
    /// skip.
    fn xorcrypt(&self, mut bits: Bits, key: &GroupElement, skip: usize) -> Bits {
        let seed = self.hash_prng(key);
        let mut prng = self.prng::<bool>(&seed).skip(skip);
        bits.iter_mut()
            .for_each(|mut i| *i.as_mut() ^= prng.next().unwrap());
        bits
    }

    /// Calculate the message authentication code.
    ///
    /// This is $\mu$ in \[DG09\].
    fn mac(&self, key: &Hash, data: &BitsSlice) -> Hash {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        for byte in data.chunks(8) {
            let byte = byte.load_le::<u8>();
            mac.update(&[byte]);
        }
        let hash: [u8; 32] = mac.finalize().into_bytes().into();
        truncate(&hash)
    }

    /// Returns the size of the "header payload" in bits.
    ///
    /// The header payload (called "final routing information" in [sphinxmix]) is the part of the
    /// header readable for the exit node.
    ///
    /// In \[DG09\], this is $|\\{\Delta || I || 0_{2(r - \upsilon) + 2)\kappa - |\Delta|}\\}|$.
    ///
    /// Note that Sphinx originally allows $|\Delta|$ to be bigger than $2\kappa$, as long as the
    /// path is short enough to leave enough space. PolySphinx always forces $|\Delta| \le
    /// 2\kappa$.
    ///
    /// [sphinxmix]: https://github.com/UCL-InfoSec/sphinx
    fn header_payload_size(&self, level: u32) -> u32 {
        if level == 0 {
            8 + F::SIZE + self.polyfier.key_size() as u32
        } else {
            8 + self.multicast_factor
                * (A::SIZE
                    + self.polyfier.token_size() as u32
                    + H::SIZE
                    + self.header_packed_size(level - 1))
        }
    }

    /// Returns the size of the header, *not* including the first hop address and MAC.
    ///
    /// This is equivalent to the size of $\beta_i$ in \[DG09\].
    fn header_beta_size(&self, level: u32) -> u32 {
        (self.max_hops - 1) * self.size_per_hop() as u32 + self.header_payload_size(level)
    }

    /// Returns the size of a packed header in bits, that is the size needed to store $(\alpha,
    /// \beta, \gamma)$.
    fn header_packed_size(&self, level: u32) -> u32 {
        // Alpha
        8 * 32 +
            // Beta
            self.header_beta_size(level) +
            // Gamma
            KAPPA as u32
    }

    /// Returns the size of data needed per hop in bits.
    fn size_per_hop(&self) -> usize {
        8 + KAPPA + A::SIZE as usize + H::SIZE as usize + self.polyfier.token_size()
    }

    /// Determine the level of this header.
    ///
    /// If the header is invalid, `None` is returned.
    fn header_level(&self, header: &Header) -> Option<u32> {
        for level in 0u32.. {
            match header
                .beta
                .len()
                .cmp(&(self.header_beta_size(level) as usize))
            {
                Ordering::Greater => (),
                Ordering::Equal => return Some(level),
                Ordering::Less => return None,
            }
        }
        unreachable!()
    }

    /// Convert a re-encryption token to a hash, suitable for seeding a PRNG.
    pub fn token_to_hash(&self, token: &P::Token) -> Hash {
        let mut result: Hash = Default::default();
        token.pack().as_raw_slice().read_exact(&mut result).unwrap();
        result
    }

    /// Create a PolySphinx header.
    ///
    /// For end-users, prefer to use [`PolySphinx::create_polyheader`] instead, which takes care of
    /// drawing the re-encryption keys.
    pub fn create_header<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        level: u32,
        header_payload: &BitsSlice,
        nodes: &[(A, PublicKey)],
        pre_keys: &[&BitsSlice],
        extender: Option<&Hash>,
    ) -> Result<Header> {
        let path_len = nodes.len();
        let max_hops = self.max_hops as usize;

        #[cfg(not(feature = "padded_header"))]
        let beta_len = self.header_beta_size(level) as usize;
        #[cfg(feature = "padded_header")]
        let beta_len = self.header_beta_size(1) as usize;

        if path_len > max_hops {
            return Err(Error::PathTooLong);
        }

        assert_eq!(
            nodes.len(),
            pre_keys.len() + 1,
            "invalid number of PRE keys"
        );
        for (i, pre_key) in pre_keys.iter().enumerate() {
            assert!(
                pre_key.len() == self.polyfier.token_size() + H::SIZE as usize,
                "key {} has wrong size: {} (expected {})",
                i,
                pre_key.len(),
                self.polyfier.token_size() + H::SIZE as usize,
            );
        }

        // Step 0: We pick a random x.
        let x = Scalar::random(&mut rng);

        // Step 1: We generate the shared secrets and blinding factors.
        let mut alphas: Vec<GroupElement> = Vec::new();
        let mut secrets: Vec<GroupElement> = Vec::new();
        let mut blindings: Vec<Scalar> = Vec::new();
        for node in nodes {
            let alpha = chain![iter::once(&x), &blindings].fold(X25519_BASEPOINT, Mul::mul);
            let secret = chain![iter::once(&x), &blindings].fold(node.1, Mul::mul);
            let blinding = self.blinding_factor(&alpha, &secret);
            alphas.push(alpha);
            secrets.push(secret);
            blindings.push(blinding);
        }

        // Step 2: Compute the filler string.
        let mut phi = Bits::new();
        for i in 1..path_len {
            phi.extend_from_bitslice(&Bits::repeat(false, self.size_per_hop()));
            phi = self.xorcrypt(
                phi,
                &secrets[i - 1],
                beta_len - (i - 1) * self.size_per_hop(),
            );

            assert_eq!(phi.len(), i * self.size_per_hop());
        }

        // Step 3: We compute the actual mix header.
        let mut beta = if level == 0 {
            HeaderFlag::Destination.to_bits()
        } else {
            HeaderFlag::Multicast.to_bits()
        };
        beta.extend_from_bitslice(header_payload);
        // Pad it
        let hp_size = self.header_payload_size(level) as usize;
        if beta.len() > hp_size {
            return Err(Error::PayloadTooLarge);
        }

        // Padding it with zeroes is a security risk, see
        // "Breaking and (Partially) Fixing Provably Secure Onion Routing"
        // Christiane Kuhn, Martin Beck, Thorsten Strufe, 2020
        let pad_length = hp_size - beta.len() + (max_hops - path_len) * self.size_per_hop();
        for _ in 0..pad_length {
            beta.push(rng.gen::<bool>());
        }

        // Extender is only given when feature padded_header is disabled
        if let Some(seed) = extender {
            let mut extension = self
                .prng::<bool>(seed)
                .take((self.header_beta_size(1) - self.header_beta_size(0)) as usize)
                .collect::<Bits>();

            // The extension is added before the first encryption, so we need to simulate that here
            for (i, secret) in secrets.iter().enumerate() {
                extension = self.xorcrypt(
                    extension,
                    secret,
                    self.header_beta_size(0) as usize - i * self.size_per_hop(),
                );
            }
            beta.extend_from_bitslice(&extension);
        }

        // Encrypt it
        beta = self.xorcrypt(beta, &secrets[path_len - 1], 0);
        beta.extend_from_bitslice(&phi);

        let mut gamma = self.mac(&self.hash_mac(&secrets[path_len - 1]), &beta);

        assert_eq!(beta.len(), beta_len);

        for i in (0..max(path_len, 1) - 1).rev() {
            let node = &nodes[i + 1];
            let mut b = HeaderFlag::Relay.to_bits();
            b.extend_from_bitslice(&node.0.pack());
            b.extend_from_raw_slice(&gamma);
            b.extend_from_bitslice(pre_keys[i]);
            b.extend_from_bitslice(&beta[0..beta_len - self.size_per_hop()]);
            beta = self.xorcrypt(b, &secrets[i], 0);

            gamma = self.mac(&self.hash_mac(&secrets[i]), &beta);
            assert_eq!(beta.len(), beta_len);
        }

        let header = Header {
            alpha: alphas[0],
            beta,
            gamma,
        };
        Ok(header)
    }

    /// Creates a nested header for the given `path`, which may contain a [`Path::Multi`]
    /// directive.
    ///
    /// This function automatically draws the reencryption keys randomly using the given PRNG
    /// (which should be cryptographically secure!) and outputs the initial key.
    ///
    /// The initial key can then be used to encrypt the message before sending it, such that each
    /// node re-encrypts the message accordingly.
    ///
    /// Note that `path` must be well-formed, which means that its max length may not exceed
    /// [`PolySphinx::max_hops`] and the multicast levels must be uniform.
    pub fn create_polyheader<R: Rng + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        path: &Path<A, H, F>,
    ) -> Result<(Header, P::EncryptionKey)> {
        if !path.is_uniform() {
            return Err(Error::NonUniformPath);
        }
        // Generate a new state for each new message
        let state = self.polyfier.prepare(&mut *rng, path)?;
        let header = self.create_polyheader_with_state(rng, path, &state.keys, None)?;
        Ok((header, state.initial_key))
    }

    fn create_polyheader_with_state<R: Rng + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        path: &Path<A, H, F>,
        state: &Tree<P::Token, P::DecryptionKey>,
        extender: Option<&Hash>,
    ) -> Result<Header> {
        let level = state.level();
        match (path, state) {
            (Path::Direct(ref nodelist, ref dest), Tree::Direct(ref pre_keys, ref final_key)) => {
                let mut header_payload = final_key.pack();
                header_payload.extend_from_bitslice(&dest.pack());
                let pre_keys = pre_keys
                    .iter()
                    .zip(nodelist)
                    .map(|(token, (_, data))| {
                        let mut bits = Bits::EMPTY;
                        bits.extend_from_bitslice(&token.pack());
                        bits.extend_from_bitslice(&data.pack());
                        bits
                    })
                    .collect::<Vec<_>>();
                let pre_keys = pre_keys
                    .iter()
                    .map(|bs| bs as &BitsSlice)
                    .collect::<Vec<_>>();
                let mix_path = nodelist.iter().map(|&(n, _)| n).collect::<Vec<_>>();
                let header = self.create_header(
                    rng,
                    level,
                    &header_payload,
                    &mix_path,
                    &pre_keys,
                    extender,
                )?;
                Ok(header)
            }

            (
                Path::Multi(ref nodelist, ref inner_paths),
                Tree::Multi(ref pre_keys, ref inner_keys),
            ) => {
                let mut header_payload = Bits::new();
                for ((next_hop, inner_path), (token, subkeys)) in inner_paths.iter().zip(inner_keys)
                {
                    #[cfg(feature = "padded_header")]
                    let extender = self.token_to_hash(&token);
                    #[cfg(feature = "padded_header")]
                    let extender = Some(&extender);
                    #[cfg(not(feature = "padded_header"))]
                    let extender = None;

                    let mut subheader = self
                        .create_polyheader_with_state(&mut *rng, inner_path, subkeys, extender)?;
                    subheader.truncate_beta(self.header_beta_size(0));
                    header_payload.extend_from_bitslice(&next_hop.0 .0.pack());
                    header_payload.extend_from_bitslice(&token.pack());
                    header_payload.extend_from_bitslice(&next_hop.1.pack());
                    header_payload.extend_from_bitslice(&subheader.pack());
                }
                let pre_keys = pre_keys
                    .iter()
                    .zip(nodelist)
                    .map(|(token, (_, data))| {
                        let mut bits = Bits::EMPTY;
                        bits.extend_from_bitslice(&token.pack());
                        bits.extend_from_bitslice(&data.pack());
                        bits
                    })
                    .collect::<Vec<_>>();
                let pre_keys = pre_keys
                    .iter()
                    .map(|bs| bs as &BitsSlice)
                    .collect::<Vec<_>>();
                let mix_path = nodelist.iter().map(|&(n, _)| n).collect::<Vec<_>>();
                let header =
                    self.create_header(rng, level, &header_payload, &mix_path, &pre_keys, None)?;
                Ok(header)
            }

            _ => panic!("Mismatched tree shapes"),
        }
    }

    /// Unwrap the header given the node's private key.
    pub fn unwrap_header(&self, priv_key: &PrivateKey, header: &Header) -> Result<Command<P, A, H, F>> {
        let level = self.header_level(header).ok_or(Error::UnknownLevel)?;

        let shared_secret = header.alpha * priv_key;
        let check_mac = self.mac(&self.hash_mac(&shared_secret), &header.beta);
        if check_mac != header.gamma {
            return Err(Error::MacMismatch);
        }

        let mut b = header.beta.clone();
        b.extend_from_bitslice(&Bits::repeat(false, self.size_per_hop()));
        b = self.xorcrypt(b, &shared_secret, 0);

        let blinding = self.blinding_factor(&header.alpha, &shared_secret);

        let flag = HeaderFlag::from_bits(&b[0..8]).ok_or(Error::InvalidFlag)?;
        match flag {
            HeaderFlag::Relay => {
                let next_hop = A::unpack(&b[8..8 + A::SIZE as usize])?;
                let pre_bits = &b[A::SIZE as usize + KAPPA + 8
                    ..A::SIZE as usize + KAPPA + 8 + self.polyfier.token_size()];
                let pre_key = P::Token::unpack(pre_bits)?;
                let extra_start = A::SIZE as usize + KAPPA + 8 + self.polyfier.token_size();
                let extra_bits = &b[extra_start..extra_start + H::SIZE as usize];
                let extra_data = H::unpack(extra_bits)?;

                let mut header = header.clone();
                header.alpha *= blinding;
                header.beta = b[self.size_per_hop()..].to_bitvec();
                header.beta.force_align();
                let new_gamma = b[A::SIZE as usize + 8..A::SIZE as usize + KAPPA + 8].to_bitvec();
                new_gamma
                    .as_raw_slice()
                    .read_exact(&mut header.gamma)
                    .unwrap();
                Ok(Command::Relay(Box::new(node::Relay {
                    next_hop,
                    next_header: header,
                    pre_key,
                    extra_data,
                })))
            }

            HeaderFlag::Destination => {
                let payload = &b[8..self.header_payload_size(0) as usize].to_bitvec();
                let decryption_key = &payload[..self.polyfier.key_size()];
                let decryption_key = P::DecryptionKey::unpack(decryption_key)?;
                let payload = payload[self.polyfier.key_size()..].to_bitvec();
                let recipient = F::unpack(&payload)?;
                Ok(Command::Destination(Box::new(node::Destination {
                    recipient,
                    decryption_key,
                })))
            }

            HeaderFlag::Multicast => {
                let payload = &b[8..self.header_payload_size(level) as usize].to_bitvec();
                let subheaders = payload
                    .chunks(
                        self.header_packed_size(level - 1) as usize
                            + A::SIZE as usize
                            + H::SIZE as usize
                            + self.polyfier.token_size(),
                    )
                    .map(|chunk| {
                        let mut chunk = chunk.to_bitvec();
                        chunk.force_align();
                        let next = A::unpack(&chunk[..A::SIZE as usize])?;
                        let pre_key = P::Token::unpack(
                            &chunk[A::SIZE as usize..A::SIZE as usize + self.polyfier.token_size()],
                        )?;
                        let extra_start = A::SIZE as usize + self.polyfier.token_size();
                        let extra_bits = &chunk[extra_start..extra_start + H::SIZE as usize];
                        let extra_data = H::unpack(extra_bits)?;
                        let subheader = Header::unpack(&chunk[extra_start + H::SIZE as usize..]);

                        #[cfg(feature = "padded_header")]
                        let mut subheader = subheader;
                        #[cfg(feature = "padded_header")]
                        subheader
                            .extend_beta(header.beta.len() as u32, &self.token_to_hash(&pre_key));

                        Ok(node::Relay {
                            next_hop: next,
                            next_header: subheader,
                            pre_key,
                            extra_data,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Command::Multicast(node::Multicast { subheaders }))
            }
        }
    }
}

/// Compute the public key for the given private key.
#[inline]
pub fn public_key(priv_key: &PrivateKey) -> PublicKey {
    X25519_BASEPOINT * priv_key
}

/// Public and private keys of a single mix node.
///
/// Useful for testing and demonstration purposes, as [`MixNode::random`] can be used to quickly
/// set up a public/private key pair for a mix node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixNode {
    /// Identifier of the mix node.
    pub identifier: Identifier,
    /// Private key of the mix node, if present.
    pub priv_key: Option<PrivateKey>,
    /// Public key of the mix node.
    pub pub_key: PublicKey,
}

impl MixNode {
    /// Generate a new random mix node.
    ///
    /// Identifier and private key are chosen randomly.
    pub fn random<R: Rng + CryptoRng>(mut rng: R) -> MixNode {
        let identifier = rng.gen();
        let priv_key = Scalar::random(&mut rng);
        let pub_key = public_key(&priv_key);
        MixNode {
            identifier,
            priv_key: Some(priv_key),
            pub_key,
        }
    }
}

impl BitPackable for u32 {
    fn pack(&self) -> Bits {
        Bits::from_slice(&self.to_be_bytes())
    }

    fn unpack(input: &BitsSlice) -> Result<Self> {
        let mut bytes = [0u8; 4];
        let mut bits = input.to_bitvec();
        bits.force_align();
        bits.as_raw_slice().read_exact(&mut bytes).unwrap();
        Ok(Self::from_be_bytes(bytes))
    }
}

impl FixedSizePackable for u32 {
    const SIZE: u32 = 32;
}

impl<A: FixedSizePackable, B: FixedSizePackable> BitPackable for (A, B) {
    fn pack(&self) -> Bits {
        let mut result = Bits::EMPTY;
        result.extend_from_bitslice(&self.0.pack());
        result.extend_from_bitslice(&self.1.pack());
        result
    }

    fn unpack(input: &BitsSlice) -> Result<Self> {
        Ok((
            A::unpack(&input[..A::SIZE as usize])?,
            B::unpack(&input[A::SIZE as usize..])?,
        ))
    }
}

impl<A: FixedSizePackable, B: FixedSizePackable> FixedSizePackable for (A, B) {
    const SIZE: u32 = A::SIZE + B::SIZE;
}
