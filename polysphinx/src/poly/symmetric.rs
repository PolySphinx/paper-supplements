//! Implements re-encryption based on AES and a deterministic key tree, as described in PolySphinx.
use aes::cipher::{KeyIvInit, StreamCipher};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

use super::{BitPackable, Polyfication, Polyfied};
use crate::{tree::Tree, Bits, BitsSlice, Error, Path, Result};

type AesCtr = ctr::Ctr64LE<aes::Aes128>;
type Seed = [u8; 16];

static IV: [u8; 16] = [0; 16];
static NULL: [u8; 16] = [0; 16];

/// A wrapper around a 128-bit AES key, implementing [`BitPackable`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AesKey(pub [u8; 16]);

impl BitPackable for AesKey {
    fn pack(&self) -> Bits {
        Bits::from_vec(bincode::serialize(self).unwrap())
    }

    fn unpack(bits: &BitsSlice) -> Result<Self> {
        bincode::deserialize(bits.to_bitvec().as_raw_slice()).map_err(|e| Error::PackingError(e))
    }
}

/// A wrapper around the key-tree seed information.
///
/// This implementation is hardcoded to a fixed upper length of 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionKey {
    /// Seed that is used to generate the key tree.
    pub keytree_seed: Seed,
    /// Path that this message took through the key tree.
    pub keytree_path: [u8; 16],
}

impl BitPackable for DecryptionKey {
    fn pack(&self) -> Bits {
        Bits::from_vec(bincode::serialize(self).unwrap())
    }

    fn unpack(bits: &BitsSlice) -> Result<Self> {
        bincode::deserialize(bits.to_bitvec().as_raw_slice()).map_err(|e| Error::PackingError(e))
    }
}

/// An implementation of [`Polyfication`] that uses different AES keys at each mix node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symmetric;

fn prepare_path<A, H, F>(
    path: &Path<A, H, F>,
    keytree: &Keytree,
    key_path: &mut Vec<u8>,
) -> Tree<AesKey, DecryptionKey> {
    match *path {
        Path::Direct(ref mixes, _) => {
            let mut keys = vec![];
            for _ in 0..mixes.len() - 1 {
                key_path.push(0);
                keys.push(AesKey(keytree.get_key(key_path)));
            }
            let mut decryption_path = [0; 16];
            (&mut decryption_path as &mut [u8])
                .write_all(key_path)
                .unwrap();
            let decryption = DecryptionKey {
                keytree_seed: keytree.seed,
                keytree_path: decryption_path,
            };

            for _ in 0..mixes.len() - 1 {
                key_path.pop();
            }

            Tree::Direct(keys, decryption)
        }

        Path::Multi(ref mixes, ref inner) => {
            let mut keys = vec![];
            for _ in 0..mixes.len() - 1 {
                key_path.push(0);
                keys.push(AesKey(keytree.get_key(key_path)));
            }

            let mut inner_keys = vec![];
            for (i, subpath) in inner.iter().enumerate() {
                key_path.push(i as u8);
                let token = AesKey(keytree.get_key(key_path));
                let inner_path = prepare_path(&subpath.1, keytree, key_path);
                inner_keys.push((token, inner_path));
                key_path.pop();
            }

            for _ in 0..mixes.len() - 1 {
                key_path.pop();
            }

            Tree::Multi(keys, inner_keys)
        }
    }
}

impl Polyfication for Symmetric {
    type EncryptionKey = AesKey;

    type DecryptionKey = DecryptionKey;

    type Token = AesKey;

    fn key_size(&self) -> usize {
        std::mem::size_of::<DecryptionKey>() * 8
    }

    fn token_size(&self) -> usize {
        16 * 8
    }

    fn prepare<R: Rng + CryptoRng, A, H, F>(
        &self,
        mut rng: R,
        path: &Path<A, H, F>,
    ) -> Result<Polyfied<Self>> {
        let seed: Seed = rng.gen();
        let keytree = Keytree { seed };
        let mut key_path = vec![];
        let keys = prepare_path(path, &keytree, &mut key_path);
        assert!(key_path.is_empty());
        Ok(Polyfied {
            initial_key: AesKey(keytree.get_key(&key_path)),
            keys,
        })
    }

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        _: R,
        key: &Self::EncryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut cipher = AesCtr::new(&key.0.into(), &IV.into());
        let mut buffer = Vec::from(NULL);
        buffer.write_all(data).unwrap();
        cipher.apply_keystream(&mut buffer);
        result.write_all(&buffer).unwrap();

        Ok(result)
    }

    fn decrypt<R: Rng + CryptoRng>(
        &self,
        _: R,
        key: &Self::DecryptionKey,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let keytree = Keytree {
            seed: key.keytree_seed,
        };
        let mut data = Vec::from(data);
        for i in 0..key.keytree_path.len() {
            if data.starts_with(&NULL) {
                return Ok(Vec::from(&data[NULL.len()..]));
            }

            let key = keytree.get_key(&key.keytree_path[..i]);
            let mut cipher = AesCtr::new(&key.into(), &IV.into());
            cipher.apply_keystream(&mut data);
        }
        panic!()
    }

    fn recrypt<R: Rng + CryptoRng>(
        &self,
        _: R,
        token: &Self::Token,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut cipher = AesCtr::new(&token.0.into(), &IV.into());
        let mut buffer = Vec::from(data);
        cipher.apply_keystream(&mut buffer);
        result.write_all(&buffer).unwrap();

        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Keytree {
    seed: Seed,
}

impl Keytree {
    fn get_key(&self, path: &[u8]) -> [u8; 16] {
        let mut current = hash(&self.seed);
        for p in path {
            for _ in 0..=*p {
                increment(&mut current);
            }
            current = hash(&current);
        }
        current
    }
}

fn hash(input: &[u8]) -> [u8; 16] {
    let mut result = [0; 16];
    result.copy_from_slice(&Sha256::digest(input).as_slice()[..16]);
    result
}

/// Treats a slice of bytes as an integer and increments it.
///
/// Returns `true` if the number wrapped around, `false` otherwise.
fn increment(x: &mut [u8]) -> bool {
    let mut carry = true;
    for v in x.iter_mut().rev() {
        if carry {
            *v = v.wrapping_add(1);
            carry = *v == 0;
        } else {
            return false;
        }
    }
    carry
}
