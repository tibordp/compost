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

use async_trait::async_trait;
use axum::extract::rejection::{TypedHeaderRejection, TypedHeaderRejectionReason};
use axum::extract::TypedHeader;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::{extract::FromRequestParts, RequestPartsExt};
use http::{request::Parts, StatusCode};

use jwt_simple::{
    algorithms::{ECDSAP256PublicKeyLike, P256PublicKey},
    claims::{JWTClaims, NoCustomClaims},
    common::VerificationOptions,
    reexports::coarsetime::Duration,
    token::Token,
};

use crate::manager::DomainKey;

use super::AppState;

const ERR_MISSING: &str = "`Authorization` header is missing";
const ERR_DECODE: &str = "`Authorization` header could not be decoded";
const ERR_INVALID: &str = "`Authorization` token invalid";

type Rejection = (StatusCode, &'static str);

#[derive(Debug, Clone)]
struct VerifyingKey(P256PublicKey);

impl From<p256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(key: p256::ecdsa::VerifyingKey) -> Self {
        // Library authors: please include a way to use the underlying
        // public key directly, without having to serialize and deserialize
        Self(unsafe { std::mem::transmute(key) })
    }
}

impl ECDSAP256PublicKeyLike for VerifyingKey {
    fn jwt_alg_name() -> &'static str {
        "ES256"
    }
    fn public_key(&self) -> &P256PublicKey {
        &self.0
    }
    fn key_id(&self) -> &Option<String> {
        &None
    }
    fn set_key_id(&mut self, _: String) {}
}

#[derive(Debug)]
pub struct Authenticated(pub DomainKey);

#[async_trait]
impl FromRequestParts<AppState> for Authenticated {
    type Rejection = Rejection;

    async fn from_request_parts(
        req: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Get authorization header
        let auth: TypedHeader<Authorization<Bearer>> =
            req.extract().await.map_err(|e: TypedHeaderRejection| {
                (
                    StatusCode::UNAUTHORIZED,
                    match e.reason() {
                        TypedHeaderRejectionReason::Missing => ERR_MISSING,
                        _ => ERR_DECODE,
                    },
                )
            })?;

        // Decode the JWT
        let metadata = Token::decode_metadata(auth.token())
            .map_err(|_| (StatusCode::UNAUTHORIZED, ERR_DECODE))?;

        let domain = metadata
            .key_id()
            .ok_or((StatusCode::UNAUTHORIZED, ERR_DECODE))?;

        let domain_key = state
            .manager
            .get_domain_key(domain, true)
            .await
            .ok()
            .flatten()
            .ok_or((StatusCode::UNAUTHORIZED, ERR_INVALID))?;

        let verifying_key = VerifyingKey::from(domain_key.verifying_key());

        let _claims: JWTClaims<NoCustomClaims> = verifying_key
            .verify_token(
                auth.token(),
                Some(VerificationOptions {
                    accept_future: false,
                    time_tolerance: Some(Duration::from_secs(10)),
                    required_subject: Some(domain.to_string()),
                    ..Default::default()
                }),
            )
            .map_err(|e| {
                tracing::debug!(
                    event = "jwt_failed",
                    error = ?e,
                    "JWT failed verification"
                );

                (StatusCode::UNAUTHORIZED, ERR_INVALID)
            })?;

        Ok(Self(domain_key))
    }
}
