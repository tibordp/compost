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

use std::borrow::Cow;
use std::fmt::Display;
use std::num::NonZeroU8;
use std::str::FromStr;
use std::time::{Duration, Instant};

use compost_crypto::EncryptedPayload;
use hickory_resolver::error::ResolveErrorKind;
use http::{HeaderMap, HeaderValue};
use mail_parser::MessageParser;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

use base64::{engine::general_purpose, Engine as _};
use elliptic_curve::pkcs8::DecodePublicKey;
use time::format_description::well_known::iso8601::TimePrecision;
use time::format_description::well_known::{iso8601::Config, Iso8601};
use time::macros::datetime;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::smtp::session::Message;
use crate::smtp::Address;
use crate::utils::trim_ascii_whitespace;

const DOMAIN_KEY_SIZE_LIMIT: usize = 500;
const WELL_KNOWN_RECORD: &str = "_compost";
const DATETIME_FORMAT: Iso8601<
    {
        Config::DEFAULT
            .set_time_precision(TimePrecision::Second {
                decimal_digits: NonZeroU8::new(3),
            })
            .encode()
    },
> = Iso8601;

time::serde::format_description!(format, OffsetDateTime, DATETIME_FORMAT);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct HashedIdentifier(pub Box<[u8]>);

impl FromStr for HashedIdentifier {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(
            general_purpose::URL_SAFE_NO_PAD
                .decode(s.as_bytes())
                .map_err(|_| ())?
                .into_boxed_slice(),
        ))
    }
}

impl Display for HashedIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", general_purpose::URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl serde::Serialize for HashedIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for HashedIdentifier {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| serde::de::Error::custom("invalid identifier"))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct InboxKey {
    pub domain_hash: HashedIdentifier,
    pub address_hash: HashedIdentifier,
    pub folder: String,
    pub datetime: time::OffsetDateTime,
    pub nonce: u32,
}

impl InboxKey {
    const SCHEMA_VERSION: u8 = 2;
    const EPOCH: OffsetDateTime = datetime!(3000-01-01 00:00:00 +00:00);

    pub fn prefix(
        domain_hash: &HashedIdentifier,
        address_hash: &HashedIdentifier,
        folder: &str,
    ) -> String {
        format!(
            "inbox/v{}/{}/{}/{}/",
            Self::SCHEMA_VERSION,
            domain_hash,
            address_hash,
            folder,
        )
    }
}

impl Display for InboxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let epoch = Self::EPOCH - self.datetime;
        let timestomp = epoch.whole_milliseconds().max(0) as u64;

        write!(
            f,
            "inbox/v{}/{}/{}/{}/{:0>14}_{:0>10}",
            Self::SCHEMA_VERSION,
            self.domain_hash,
            self.address_hash,
            self.folder,
            timestomp,
            self.nonce,
        )
    }
}

impl FromStr for InboxKey {
    type Err = ();

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut parts = s.split('/');

        if parts.next() != Some("inbox") {
            return Err(());
        }
        if parts.next() != Some(format!("v{}", Self::SCHEMA_VERSION).as_str()) {
            return Err(());
        }

        let domain_hash = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let address_hash = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let folder = parts.next().ok_or(())?.to_string();
        let mut last_part = parts.next().ok_or(())?.split('_');

        let timestamp: u64 = last_part.next().ok_or(())?.parse().map_err(|_| ())?;
        let datetime = Self::EPOCH - time::Duration::milliseconds(timestamp as _);

        let nonce = last_part.next().ok_or(())?.parse().map_err(|_| ())?;
        if last_part.next().is_some() {
            return Err(());
        }

        if parts.next().is_some() {
            return Err(());
        }

        Ok(Self {
            domain_hash,
            address_hash,
            folder,
            datetime,
            nonce,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InboxEntry {
    pub from: Vec<mail_parser::Addr<'static>>,
    pub subject: Option<String>,
    #[serde(with = "format")]
    pub datetime: time::OffsetDateTime,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct DirectoryKey {
    pub domain_hash: HashedIdentifier,
    pub address_hash: HashedIdentifier,
}

impl DirectoryKey {
    const SCHEMA_VERSION: u8 = 1;

    pub fn prefix(domain_hash: &HashedIdentifier) -> String {
        format!("directory/v{}/{}/", Self::SCHEMA_VERSION, domain_hash,)
    }
}

impl Display for DirectoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "directory/v{}/{}/{}",
            Self::SCHEMA_VERSION,
            self.domain_hash,
            self.address_hash,
        )
    }
}

impl FromStr for DirectoryKey {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = s.split('/');

        if parts.next() != Some("directory") {
            return Err(());
        }
        if parts.next() != Some(format!("v{}", Self::SCHEMA_VERSION).as_str()) {
            return Err(());
        }

        let domain_hash = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let address_hash = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        if parts.next().is_some() {
            return Err(());
        }

        Ok(Self {
            domain_hash,
            address_hash,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DomainKey {
    pub domain: String,
    pub public_key: p256::PublicKey,
    pub salt: Option<Box<[u8]>>,
}

impl DomainKey {
    pub fn from_txt(domain: String, txt: &[Box<[u8]>]) -> Result<Self> {
        let merged = txt.concat();

        // Early filtering of obviously wrong DKs
        if merged.len() > DOMAIN_KEY_SIZE_LIMIT {
            return Err(Error::InvalidDomainKey);
        }

        let mut public_key = None;
        let mut salt = None;

        for part in merged.split(|b| *b == b';') {
            let part = trim_ascii_whitespace(part);

            if let Some(encoded) = part.strip_prefix(b"key=") {
                let key = general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| Error::InvalidDomainKey)?;

                if public_key
                    .replace(
                        p256::PublicKey::from_public_key_der(&key)
                            .map_err(|_| Error::InvalidDomainKey)?,
                    )
                    .is_some()
                {
                    return Err(Error::InvalidDomainKey);
                }
            }

            if let Some(encoded) = part.strip_prefix(b"salt=") {
                if salt
                    .replace(
                        general_purpose::STANDARD
                            .decode(encoded)
                            .map_err(|_| Error::InvalidDomainKey)?
                            .into_boxed_slice(),
                    )
                    .is_some()
                {
                    return Err(Error::InvalidDomainKey);
                }
            }
        }

        Ok(Self {
            domain: domain.trim_end_matches('.').to_lowercase(),
            public_key: public_key.ok_or(Error::InvalidDomainKey)?,
            salt,
        })
    }

    /// Hash an identifier (e.g. a domain name) for storage to provide some degree
    /// of privacy if the DB is ever compromised.
    ///
    /// It only prevents trivial enumeration of domains and inboxes, but will not
    /// provide plausible deniability.
    pub fn hkdf_identifier(&self, ikm: &[u8]) -> HashedIdentifier {
        let mut digest = Box::new([0u8; 16]);
        hkdf::Hkdf::<sha2::Sha256>::new(self.salt.as_deref(), ikm)
            .expand(b"", &mut *digest)
            .expect("invalid length");

        HashedIdentifier(digest)
    }

    pub fn domain_hash(&self) -> HashedIdentifier {
        self.hkdf_identifier(self.domain.as_bytes())
    }

    /// Encrypt a message for this domain.
    ///
    /// This provides a much greater degree of privacy than the HKDF identifier,
    /// as we do not possess the private key.
    pub fn encrypt(&self, plaintext: &[u8]) -> EncryptedPayload {
        compost_crypto::encrypt(&self.public_key, plaintext)
    }

    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        self.public_key.into()
    }
}

pub struct SigningKeyExpiry;

type DomainKeyCacheEntry = (Instant, Option<DomainKey>);

impl moka::Expiry<String, DomainKeyCacheEntry> for SigningKeyExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &DomainKeyCacheEntry,
        created_at: Instant,
    ) -> Option<std::time::Duration> {
        Some(value.0.saturating_duration_since(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &DomainKeyCacheEntry,
        updated_at: Instant,
        _duration_until_expiry: Option<std::time::Duration>,
    ) -> Option<std::time::Duration> {
        Some(value.0.saturating_duration_since(updated_at))
    }
}

pub struct Manager {
    pub bucket: s3::Bucket,
    pub resolver: hickory_resolver::TokioAsyncResolver,
    pub domain_keys: moka::sync::Cache<String, DomainKeyCacheEntry>,
}

fn to_fqdn(domain: &str) -> Cow<'_, str> {
    if domain.ends_with('.') {
        domain.into()
    } else {
        format!("{}.", domain).into()
    }
}

impl Manager {
    pub fn new(resolver: hickory_resolver::TokioAsyncResolver, bucket: s3::Bucket) -> Self {
        Self {
            bucket,
            resolver,
            domain_keys: moka::sync::Cache::builder()
                .max_capacity(1024)
                .expire_after(SigningKeyExpiry)
                .build(),
        }
    }

    /// Get the signing key for the given domain, if it exists.
    pub async fn get_domain_key(&self, domain: &str, cache_nx: bool) -> Result<Option<DomainKey>> {
        if let Some(key) = self.domain_keys.get(domain) {
            return Ok(key.1);
        }

        let query_start = Instant::now();

        let full_domain = format!("{}.{}", WELL_KNOWN_RECORD, to_fqdn(domain));
        let valid_until = match self.resolver.txt_lookup(&full_domain).await {
            Ok(res) => {
                let valid_until = res.valid_until();
                for txt in res {
                    match DomainKey::from_txt(domain.to_string(), txt.txt_data()) {
                        Ok(key) => {
                            self.domain_keys
                                .insert(domain.to_string(), (valid_until, Some(key.clone())));
                            return Ok(Some(key));
                        }
                        Err(_) => {
                            tracing::warn!(domain = domain, "invalid domain key",);
                        }
                    }
                }
                Some(valid_until)
            }
            Err(e) => match e.kind() {
                ResolveErrorKind::NoRecordsFound { negative_ttl, .. } => {
                    negative_ttl.map(|s| query_start + Duration::from_secs(s as _))
                }
                _ => return Err(e.into()),
            },
        };

        if let Some(valid_until) = valid_until {
            if cache_nx {
                self.domain_keys
                    .insert(domain.to_string(), (valid_until, None));
            }
        }

        Ok(None)
    }

    pub async fn recipient_allowed(&self, address: &Address) -> Result<bool> {
        if cfg!(test) {
            if address.domain == "bad.com" {
                return Ok(false);
            }
            if address.domain == "fail.com" {
                return Err(crate::error::Error::InvalidRecepient);
            }
        }

        let has_domain_key = self
            .get_domain_key(address.domain.as_str(), true)
            .await?
            .is_some();

        Ok(has_domain_key)
    }

    pub async fn store_message(&self, mut message: Message) -> Result<()> {
        let headers = MessageParser::default()
            .parse_headers(&message.body)
            .ok_or(Error::MalformedMessage)?;

        // Sorted by domain
        message.recipients.sort_unstable();

        let mut to_deliver = Vec::with_capacity(message.recipients.len());
        let mut last_domain = None;

        for recpt in message.recipients.iter() {
            if last_domain.as_ref() != Some(&recpt.domain) {
                // Domain key disappeared after we've validated the recipient
                // This should happen only very rarely (or if someone is trying some shenanigans).
                // In this case we drop the message (before we've written the inbox entry, so it's
                // not visible).
                let Some(domain_key) = self.get_domain_key(&recpt.domain, true).await? else {
                    return Err(Error::InvalidRecepient);
                };

                let encrypted = domain_key.encrypt(&message.body);
                let bytes = encrypted.to_bytes();

                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hash = hasher.finalize();

                let blob_key = format!("blobs/{}", general_purpose::URL_SAFE.encode(hash));
                self.bucket.put_object(&blob_key, &bytes).await?;

                tracing::info!(
                    blob_key = ?blob_key,
                    "stored message"
                );

                last_domain = Some(recpt.domain.clone());
                to_deliver.push((recpt, domain_key, blob_key));
            } else {
                let mut new = to_deliver.last().cloned().unwrap();
                new.0 = recpt;

                to_deliver.push(new);
            }
        }

        for (recpt, domain_key, blob_key) in to_deliver {
            let inbox_entry = InboxEntry {
                datetime: message.created,
                from: headers
                    .from()
                    .cloned()
                    .into_iter()
                    .flat_map(|f| match f.into_owned() {
                        mail_parser::Address::List(l) => l,
                        mail_parser::Address::Group(_) => Vec::new(),
                    })
                    .collect(),
                subject: headers.subject().map(|s| s.to_owned()),
            };
            let index_entry = domain_key.encrypt(
                serde_json::to_string(&inbox_entry)
                    .expect("failed to serialize inbox entry")
                    .as_bytes(),
            );

            let nonce = rand::thread_rng().next_u32();
            let inbox_key = InboxKey {
                domain_hash: domain_key.domain_hash(),
                address_hash: domain_key.hkdf_identifier(recpt.address_lcase.as_bytes()),
                folder: "_default".to_string(),
                datetime: message.created,
                nonce,
            };

            let mut extra_headers: HeaderMap<HeaderValue> = HeaderMap::with_capacity(1);
            extra_headers.append(
                "x-amz-meta-blob-key",
                HeaderValue::from_str(&blob_key).unwrap(),
            );

            self.bucket
                .with_extra_headers(extra_headers)?
                .put_object(inbox_key.to_string(), &index_entry.to_bytes())
                .await?;

            let directory_key = DirectoryKey {
                domain_hash: inbox_key.domain_hash.clone(),
                address_hash: inbox_key.address_hash.clone(),
            };
            self.bucket
                .put_object(
                    directory_key.to_string(),
                    &domain_key.encrypt(recpt.address.as_bytes()).to_bytes(),
                )
                .await?;
        }

        Ok(())
    }

    pub fn bucket(&self) -> &s3::Bucket {
        &self.bucket
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_inbox_key() {
        let key = InboxKey {
            domain_hash: HashedIdentifier(Box::new([0u8; 16])),
            address_hash: HashedIdentifier(Box::new([0u8; 16])),
            folder: "_default".to_string(),
            datetime: time::OffsetDateTime::from_unix_timestamp(0).unwrap(),
            nonce: 0,
        };

        assert_eq!(
            key.to_string(),
            concat!(
                "inbox/v2/AAAAAAAAAAAAAAAAAAAAAA/",
                "AAAAAAAAAAAAAAAAAAAAAA/_default/",
                "32503680000000_0000000000"
            )
        );

        assert_eq!(key.to_string().parse::<InboxKey>(), Ok(key));
    }

    #[test]
    fn test_directory_key() {
        let key = DirectoryKey {
            domain_hash: HashedIdentifier(Box::new([0u8; 16])),
            address_hash: HashedIdentifier(Box::new([0u8; 16])),
        };

        assert_eq!(
            key.to_string(),
            concat!(
                "directory/v1/AAAAAAAAAAAAAAAAAAAAAA",
                "/AAAAAAAAAAAAAAAAAAAAAA"
            )
        );

        assert_eq!(key.to_string().parse::<DirectoryKey>().unwrap(), key);
    }
}
