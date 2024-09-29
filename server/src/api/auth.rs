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
use axum::http::{request::Parts, StatusCode};
use axum::{extract::FromRequestParts, RequestPartsExt};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::typed_header::{TypedHeader, TypedHeaderRejection, TypedHeaderRejectionReason};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use serde::Deserialize;

use crate::manager::DomainKey;

use super::AppState;

const ERR_MISSING: &str = "`Authorization` header is missing";
const ERR_DECODE: &str = "`Authorization` header could not be decoded";
const ERR_INVALID: &str = "`Authorization` token invalid";

type Rejection = (StatusCode, &'static str);

/// The leeway for token validation in seconds
const LEEWAY: usize = 10;

#[derive(Debug, Deserialize)]
pub enum Algorithm {
    ES256,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    //pub alg: Algorithm,
    pub kid: String,
}

#[derive(Debug, Deserialize)]
pub struct Payload {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
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
        let token = auth.token();

        // All JWT libraries are terrible, so we do this on our own
        let split = token.rsplitn(2, '.').collect::<Vec<_>>();
        let (signature, message) = match split.as_slice() {
            [signature, message] => (signature, message),
            _ => return Err((StatusCode::UNAUTHORIZED, ERR_DECODE)),
        };

        let split = message.rsplitn(2, '.').collect::<Vec<_>>();
        let (payload, header) = match split.as_slice() {
            [payload, header] => (payload, header),
            _ => return Err((StatusCode::UNAUTHORIZED, ERR_DECODE)),
        };

        let header = URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| (StatusCode::UNAUTHORIZED, ERR_DECODE))?;
        let header: Header =
            serde_json::from_slice(&header).map_err(|_| (StatusCode::UNAUTHORIZED, ERR_DECODE))?;

        let domain_key = state
            .manager
            .get_domain_key(&header.kid, true)
            .await
            .ok()
            .flatten()
            .ok_or((StatusCode::UNAUTHORIZED, ERR_INVALID))?;

        let verifying_key = domain_key.verifying_key();
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|s| Signature::from_slice(&s).ok())
            .ok_or((StatusCode::UNAUTHORIZED, ERR_DECODE))?;

        verifying_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| (StatusCode::UNAUTHORIZED, ERR_INVALID))?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| (StatusCode::UNAUTHORIZED, ERR_INVALID))?;
        let payload: Payload = serde_json::from_slice(&payload)
            .map_err(|_| (StatusCode::UNAUTHORIZED, ERR_INVALID))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        if payload.exp + LEEWAY < now || payload.iat > now + LEEWAY {
            return Err((StatusCode::UNAUTHORIZED, ERR_INVALID));
        }

        if payload.sub != domain_key.domain {
            return Err((StatusCode::UNAUTHORIZED, ERR_INVALID));
        }

        Ok(Self(domain_key))
    }
}
