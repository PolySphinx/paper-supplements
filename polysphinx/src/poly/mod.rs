//! Abstraction for the ciphertext duplication mechanism.
//!
//! As a consumer of PolySphinx, you do not need to concern yourself too much with the contents of
//! this module. The [`PolySphinx`][crate::PolySphinx] struct provides everything you need.
//!
//! If you plan on extending PolySphinx by providing a different mechanism to create
//! indistinguishable ciphertext copies, take a look at the [`Polyfication`] trait.
use crate::{tree::Tree, Bits, BitsSlice, Path, Result};
use rand::{CryptoRng, Rng};
use std::fmt::Debug;

pub mod symmetric;
pub use self::symmetric::Symmetric;

/// A trait that allows objects to be bit-packed.
pub trait BitPackable: Sized {
    /// Pack this struct into a compact bit representation.
    fn pack(&self) -> Bits;
    /// Unpack this struct from its compact bit representation.
    fn unpack(input: &BitsSlice) -> Result<Self>;
}

/// Main trait to capture the "Polyfication".
///
/// The polyfication process creates multiple ciphertext copies from a single input ciphertext. How
/// exactly that works is up to the implementor. Ideas include (but are not limited to):
///
/// * Using different AES keys to generate indistinguishable ciphertexts.
/// * Using re-randomization for the ciphertexts \[1\]
/// * Using homomorphic encryption \[2\]
///
/// \[1\]: Universal Re-encryption for mixnets - Philippe Golle, Markus Jakobsson, Ari Juels, Paul
/// Syverson
///
/// \[2\]: Key Homomorphic PRFs and Their Applications - Dan Boneh, Kevin Lewi, Hart Montgomery,
/// Ananth Raghunathan
pub trait Polyfication: Sized {
    /// The type of an encryption key.
    type EncryptionKey: BitPackable + Clone + Eq + Debug;
    /// The type of an decryption key.
    type DecryptionKey: BitPackable + Clone + Eq + Debug;
    /// The type of a re-encryption token.
    type Token: BitPackable + Clone + Eq + Debug;

    /// Returns the size of a [`Self::DecryptionKey`] in bits.
    fn key_size(&self) -> usize;
    /// Returns the size of a [`Self::Token`] in bits.
    fn token_size(&self) -> usize;

    /// Prepare a polyfication for the given path.
    ///
    /// This function is responsible for generating all necessary keys and returning them in a
    /// [`Polyfied`] container, which is then used to embed the values into the PolySphinx header.
    fn prepare<R: Rng + CryptoRng, A, H, F>(
        &self,
        rng: R,
        path: &Path<A, H, F>,
    ) -> Result<Polyfied<Self>>;

    /// Encrypt the data with the given key.
    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::EncryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>>;
    /// Decrypt the data with the given key.
    fn decrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::DecryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>>;
    /// Re-encrypt the data with the given re-encryption token.
    fn recrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        token: &Self::Token,
        data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Result of a polyification.
pub struct Polyfied<P: Polyfication> {
    /// Initial key.
    ///
    /// This is the key that the sender must use to prepare the payload before sending it.
    pub initial_key: P::EncryptionKey,
    /// Tree of re-encryption keys for the mix nodes.
    ///
    /// Each mix node is assigned a token for the re-encryption operation. The final mix node also
    /// gets a decryption key, so it can unwrap the inner messages.
    pub keys: Tree<P::Token, P::DecryptionKey>,
}

/// Helper function to implement [`Polyfication`].
///
/// This can be used if the re-encryption and decryption keys do not depend on the path of the
/// message, as then the given generators can be used to generate keys and tokens.
///
/// The `generate_key` function is used to generate a key for a node (independently of the node's
/// position), and the `generate_token` function is used to generate a token to go from one key to
/// the next.
pub fn polyfy_from_generators<P, R, F, G, K, A, H, D>(
    rng: &mut R,
    path: &Path<A, H, D>,
    generate_key: &mut F,
    generate_token: &mut G,
) -> Polyfied<P>
where
    R: Rng + CryptoRng,
    K: Clone,
    P: Polyfication<EncryptionKey = K, DecryptionKey = K>,
    F: FnMut(&mut R) -> K,
    G: FnMut(&mut R, &K, &K) -> P::Token,
{
    match *path {
        Path::Direct(ref edges, _) => {
            let keys = (0..edges.len())
                .map(|_| generate_key(&mut *rng))
                .collect::<Vec<_>>();
            let tokens = keys
                .iter()
                .zip(keys.iter().skip(1))
                .map(|(from, to)| generate_token(&mut *rng, from, to))
                .collect::<Vec<_>>();
            assert_eq!(edges.len(), tokens.len() + 1);
            Polyfied {
                initial_key: keys.first().unwrap().clone(),
                keys: Tree::Direct(tokens, keys.last().unwrap().clone()),
            }
        }

        Path::Multi(ref edges, ref inner) => {
            let keys = (0..edges.len())
                .map(|_| generate_key(&mut *rng))
                .collect::<Vec<_>>();
            let tokens = keys
                .iter()
                .zip(keys.iter().skip(1))
                .map(|(from, to)| generate_token(&mut *rng, from, to))
                .collect::<Vec<_>>();
            assert_eq!(edges.len(), tokens.len() + 1);
            let final_key = keys.last().unwrap();

            let inners = inner
                .iter()
                .map(|(_, inner_path)| {
                    polyfy_from_generators::<P, _, _, _, _, _, _, _>(
                        &mut *rng,
                        inner_path,
                        &mut *generate_key,
                        &mut *generate_token,
                    )
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|polyfied| {
                    (
                        generate_token(&mut *rng, final_key, &polyfied.initial_key),
                        polyfied.keys,
                    )
                })
                .collect::<Vec<_>>();

            Polyfied {
                initial_key: keys.first().unwrap().clone(),
                keys: Tree::Multi(tokens, inners),
            }
        }
    }
}
