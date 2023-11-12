/*
 * Compost Mail Server
 *
 * Copyright (c) 2023 Tibor Djurica Potpara
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//! ECIES encryption and decryption.
//!
//! Uses NIST P-256 for DH, AES-256-GCM for encryption, and HKDF-SHA256 for key derivation.

#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use elliptic_curve::pkcs8::EncodePrivateKey;
use pbkdf2::pbkdf2_hmac;
use rand_chacha::ChaCha20Rng;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use elliptic_curve::pkcs8::{DecodePublicKey, EncodePublicKey};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hkdf::Hkdf;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit;

const SCHEMA_VERSION: [u8; 4] = [0, 0, 0, 1];

const ENCRYPTION_KEY_LEN: usize = 32;
const ENCRYPTION_NONCE_LEN: usize = 12;
const PUBLIC_KEY_LEN: usize = 33;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Debug)]
pub struct EncryptedPayload {
    public_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl EncryptedPayload {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new(
        public_key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<EncryptedPayload, Error> {
        if public_key.len() != PUBLIC_KEY_LEN
            || nonce.len() != ENCRYPTION_NONCE_LEN
            || ciphertext.is_empty()
        {
            return Err(Error);
        }

        Ok(Self {
            public_key,
            nonce,
            ciphertext,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptedPayload, Error> {
        if bytes.len() <= SCHEMA_VERSION.len() + PUBLIC_KEY_LEN + ENCRYPTION_NONCE_LEN {
            return Err(Error);
        }

        if bytes[0..SCHEMA_VERSION.len()] != SCHEMA_VERSION {
            return Err(Error);
        }

        Ok(Self {
            public_key: bytes[SCHEMA_VERSION.len()..SCHEMA_VERSION.len() + PUBLIC_KEY_LEN].to_vec(),
            nonce: bytes[SCHEMA_VERSION.len() + PUBLIC_KEY_LEN
                ..SCHEMA_VERSION.len() + PUBLIC_KEY_LEN + ENCRYPTION_NONCE_LEN]
                .to_vec(),
            ciphertext: bytes[SCHEMA_VERSION.len() + PUBLIC_KEY_LEN + ENCRYPTION_NONCE_LEN..]
                .to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            SCHEMA_VERSION.len() + ENCRYPTION_NONCE_LEN + PUBLIC_KEY_LEN + self.ciphertext.len(),
        );

        bytes.extend_from_slice(&SCHEMA_VERSION);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[derive(Debug)]
pub struct Error;

/// Convert a compressed public key to SPKI format (in DER encoding).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn public_key_to_der(public_key: &[u8]) -> Result<Vec<u8>, Error> {
    let encoded_point = p256::EncodedPoint::from_bytes(public_key).map_err(|_| Error)?;
    let public_key: Option<_> = p256::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key: p256::PublicKey = public_key.ok_or(Error)?;

    Ok(public_key
        .to_public_key_der()
        .map_err(|_| Error)?
        .into_vec())
}

/// Encrypt a message using the given public key.
pub fn encrypt(public_key: &p256::PublicKey, plaintext: &[u8]) -> EncryptedPayload {
    let mut rng = rand_core::OsRng;

    let ephemeral_secret = p256::ecdh::EphemeralSecret::random(&mut rng);
    let ephemeral_public = ephemeral_secret.public_key();

    let mut nonce = vec![0u8; ENCRYPTION_NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let ephemeral_public_enc = ephemeral_public.to_encoded_point(true).as_bytes().to_vec();

    // Derive
    let mut shared_secret = ephemeral_secret
        .diffie_hellman(public_key)
        .raw_secret_bytes()
        .to_vec();
    shared_secret.extend_from_slice(&ephemeral_public_enc);

    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut derived_key = vec![0u8; ENCRYPTION_KEY_LEN];

    hkdf.expand(b"", &mut derived_key).expect("expand OK");

    let enc = aes_gcm::Aes256Gcm::new_from_slice(&derived_key).expect("new_from_slice OK");

    let ciphertext = enc
        .encrypt(
            nonce[..].into(),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .expect("encrypt OK");

    EncryptedPayload {
        nonce,
        public_key: ephemeral_public_enc,
        ciphertext,
    }
}

/// Encrypt a message using the given public key in DER format (SPKI format).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encrypt_der(public_key: &[u8], plaintext: &[u8]) -> Result<EncryptedPayload, Error> {
    let public_key = p256::PublicKey::from_public_key_der(public_key).map_err(|_| Error)?;

    Ok(encrypt(&public_key, plaintext))
}

/// Decrypt a message using the given private key.
pub fn decrypt(
    private_key: &p256::SecretKey,
    encrypted: &EncryptedPayload,
) -> Result<Vec<u8>, Error> {
    let encoded_point = p256::EncodedPoint::from_bytes(&encrypted.public_key).map_err(|_| Error)?;
    let ephemeral_pk: Option<_> = p256::PublicKey::from_encoded_point(&encoded_point).into();
    let ephemeral_pk: p256::PublicKey = ephemeral_pk.ok_or(Error)?;

    let agreement =
        p256::ecdh::diffie_hellman(private_key.to_nonzero_scalar(), ephemeral_pk.as_affine());

    decrypt_fom_dh(agreement.raw_secret_bytes(), encrypted)
}

/// Decrypt a message using the given Diffie-Hellman agreement.
///
/// This is exported to WebAssembly so that DH agreement can be done in the browser without having
/// to export the private key.
///
/// # Errors
///
/// Returns `Err` if the ciphertext is invalid for any reason.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decrypt_fom_dh(agreement: &[u8], encrypted: &EncryptedPayload) -> Result<Vec<u8>, Error> {
    let mut shared_secret = Vec::with_capacity(agreement.len() + encrypted.public_key.len());
    shared_secret.extend_from_slice(agreement);
    shared_secret.extend_from_slice(&encrypted.public_key);

    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut derived_key = vec![0u8; ENCRYPTION_KEY_LEN];

    hkdf.expand(b"", &mut derived_key).unwrap();

    let dec = aes_gcm::Aes256Gcm::new_from_slice(&derived_key).unwrap();

    dec.decrypt(
        encrypted.nonce[..].into(),
        Payload {
            msg: &encrypted.ciphertext,
            aad: b"",
        },
    )
    .map_err(|_| Error)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct KeyPair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl KeyPair {
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }

    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_private_key(mnemonic: &[u8]) -> Result<KeyPair, Error> {
    let salt = b"compostmail";

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(mnemonic, salt, 65536, &mut key);

    let secret_key = p256::SecretKey::random(&mut ChaCha20Rng::from_seed(key));
    let public_key = secret_key.public_key();

    let secret = secret_key
        .to_pkcs8_der()
        .map_err(|_| Error)?
        .as_bytes()
        .to_vec();
    let public = public_key
        .to_public_key_der()
        .map_err(|_| Error)?
        .into_vec();

    Ok(KeyPair { secret, public })
}

#[cfg(test)]
mod test {
    use super::*;

    use elliptic_curve::pkcs8::DecodePrivateKey;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"Hello, world!";

        let private_key = p256::SecretKey::random(&mut rand_core::OsRng);
        let public_key = private_key.public_key();

        let encrypted = encrypt(&public_key, plaintext);

        let decrypted = decrypt(&private_key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_ciphertext() {
        let plaintext = b"Hello, world!";

        let private_key = p256::SecretKey::random(&mut rand_core::OsRng);
        let public_key = private_key.public_key();

        let mut encrypted = encrypt(&public_key, plaintext);
        encrypted.ciphertext[0] ^= 1;

        decrypt(&private_key, &encrypted).unwrap_err();
    }

    #[test]
    fn test_encrypt_decrypt_invalid_nonce() {
        let plaintext = b"Hello, world!";

        let private_key = p256::SecretKey::random(&mut rand_core::OsRng);
        let public_key = private_key.public_key();

        let mut encrypted = encrypt(&public_key, plaintext);
        encrypted.nonce[0] ^= 1;

        decrypt(&private_key, &encrypted).unwrap_err();
    }

    #[test]
    fn test_encrypt_decrypt_invalid_public_key() {
        let plaintext = b"Hello, world!";

        let private_key = p256::SecretKey::random(&mut rand_core::OsRng);
        let public_key = private_key.public_key();

        let mut encrypted = encrypt(&public_key, plaintext);
        encrypted.public_key[0] ^= 1;

        decrypt(&private_key, &encrypted).unwrap_err();
    }

    #[test]
    fn test_serialize() {
        let payload = EncryptedPayload {
            public_key: vec![1; PUBLIC_KEY_LEN],
            nonce: vec![2; ENCRYPTION_NONCE_LEN],
            ciphertext: vec![3, 4, 5, 6, 7, 8, 9],
        };

        let bytes = payload.to_bytes();
        assert_eq!(
            bytes,
            vec![
                // schema version
                0, 0, 0, 1, // public key
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, // nonce
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // ciphertext
                3, 4, 5, 6, 7, 8, 9
            ]
        );
    }

    #[test]
    fn test_deserialize() {
        let bytes = vec![
            // schema version
            0, 0, 0, 1, // public key
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, // nonce
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // ciphertext
            3, 4, 5, 6, 7, 8, 9,
        ];

        let payload = EncryptedPayload::from_bytes(&bytes).unwrap();

        assert_eq!(payload.public_key, vec![1; PUBLIC_KEY_LEN]);
        assert_eq!(payload.nonce, vec![2; ENCRYPTION_NONCE_LEN]);
        assert_eq!(payload.ciphertext, vec![3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_deserialize_invalid() {
        EncryptedPayload::from_bytes(&[
            // schema version
            0, 0, 0, 2, // public key
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, // nonce
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // ciphertext
            3, 4, 5, 6, 7, 8, 9,
        ])
        .expect_err("invalid schema version");

        EncryptedPayload::from_bytes(&[
            // schema version
            0, 0, 0, 1, // public key
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, // nonce
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ])
        .expect_err("missing ciphertext");

        EncryptedPayload::from_bytes(&[
            // schema version
            0, 0, 0, 1, // public key
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, // nonce
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ])
        .expect_err("truncated nonce");

        EncryptedPayload::from_bytes(&[
            // schema version
            0, 0, 0, 1,
            // public key
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ]).expect_err("truncated public key");
    }

    #[test]
    fn test_derive_private_key_stability() {
        let KeyPair { secret, public } = derive_private_key(b"hunter2").unwrap();

        let secret_key = p256::SecretKey::from_pkcs8_der(&secret).unwrap();
        let public_key = p256::PublicKey::from_public_key_der(&public).unwrap();

        assert_eq!(secret_key.public_key(), public_key);
        assert_eq!(
            secret_key.to_bytes().as_slice(),
            &[
                163, 51, 192, 103, 226, 60, 167, 150, 42, 135, 70, 207, 167, 65, 231, 250, 82, 212,
                199, 156, 19, 178, 38, 97, 159, 220, 233, 92, 60, 156, 102, 95
            ]
        );
    }
}
