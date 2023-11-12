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

mod auth;

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use axum_prometheus::GenericMetricLayer;
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose, Engine};

use elliptic_curve::pkcs8::EncodePublicKey;
use futures::{StreamExt, TryStreamExt};
use http::{Method, StatusCode};

use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::watch;
use tower_http::cors::Any;

use crate::{
    error::Error,
    listener::Listener,
    manager::{self, DirectoryKey, HashedIdentifier, InboxKey, Manager},
    tls::TlsProvider,
};

use self::auth::Authenticated;

const PARALLELISM: usize = 32;

struct Encrypted(Vec<u8>);

impl serde::Serialize for Encrypted {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Encrypted {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Account {
    id: HashedIdentifier,
    email_encrypted: Encrypted,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Message {
    id: String,
    blob_url: String,
    metadata_encrypted: Encrypted,
}

#[derive(serde::Deserialize)]
struct DomainQuery {
    domain: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DomainKey {
    domain: String,
    salt: Option<String>,
    public_key: String,
}

impl TryFrom<manager::DomainKey> for DomainKey {
    type Error = Error;

    fn try_from(value: manager::DomainKey) -> Result<Self, Self::Error> {
        let public_key = value
            .public_key
            .to_public_key_der()
            .map_err(|_| Error::InvalidDomainKey)?;

        Ok(DomainKey {
            domain: value.domain,
            salt: value
                .salt
                .as_deref()
                .map(|s| general_purpose::STANDARD.encode(s)),
            public_key: general_purpose::STANDARD.encode(public_key.as_bytes()),
        })
    }
}

/// Health check endpoint
async fn healthz() -> &'static str {
    "OK"
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let code = match self {
            Error::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (code, self.to_string()).into_response()
    }
}

async fn directory(
    Authenticated(domain_key): Authenticated,
    State(state): State<AppState>,
) -> Result<Json<Vec<Account>>, Error> {
    let bucket = state.manager.bucket();
    let domain_hash = domain_key.domain_hash();

    let (tx, rx) = tokio::sync::mpsc::channel(PARALLELISM * 2);
    let list_fut = async move {
        let mut continuation_token = None;
        loop {
            let (list_bucket_result, _) = bucket
                .list_page(
                    DirectoryKey::prefix(&domain_hash),
                    None,
                    continuation_token,
                    None,
                    None,
                )
                .await?;
            continuation_token = list_bucket_result.next_continuation_token.clone();

            for object in list_bucket_result.contents {
                let _ = tx.send(object.key).await;
            }

            if continuation_token.is_none() {
                break;
            }
        }

        Ok::<_, Error>(())
    };

    let results_fut = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(|object_key| async move {
            let Ok(key): std::result::Result<DirectoryKey, _> = object_key.parse() else {
                return None;
            };

            let res = match bucket.get_object(&object_key).await {
                Ok(res) => res,
                Err(e) => {
                    return Some(Err(e.into()));
                }
            };

            Some(Ok(Account {
                id: key.address_hash,
                email_encrypted: Encrypted(res.to_vec()),
            }))
        })
        .buffer_unordered(PARALLELISM)
        .filter_map(futures::future::ready)
        .try_collect::<Vec<_>>();

    let (results, _) = tokio::try_join!(results_fut, list_fut)?;
    Ok(Json(results))
}

#[derive(serde::Deserialize, Default)]
struct InboxQuery {
    limit: Option<usize>,
}

async fn inbox(
    Authenticated(domain_key): Authenticated,
    State(state): State<AppState>,
    Path(account): Path<HashedIdentifier>,
    Query(query): Query<InboxQuery>,
) -> Result<Json<Vec<Message>>, Error> {
    let bucket = state.manager.bucket();
    let domain_hash = domain_key.domain_hash();

    let (tx, rx) = tokio::sync::mpsc::channel(PARALLELISM * 2);
    let list_fut = async move {
        let mut continuation_token = None;
        let mut remaining = query.limit;

        'outer: loop {
            let (list_bucket_result, _) = bucket
                .list_page(
                    InboxKey::prefix(&domain_hash, &account, "_default"),
                    None,
                    continuation_token,
                    None,
                    None,
                )
                .await?;
            continuation_token = list_bucket_result.next_continuation_token.clone();

            for object in list_bucket_result.contents {
                if remaining
                    .as_mut()
                    .map(|a| {
                        let b = *a;
                        *a = b.saturating_sub(1);
                        b > 0
                    })
                    .unwrap_or(true)
                {
                    let _ = tx.send(object.key).await;
                } else {
                    break 'outer;
                }
            }

            if continuation_token.is_none() {
                break;
            }
        }

        Ok::<_, Error>(())
    };

    let results_fut = tokio_stream::wrappers::ReceiverStream::new(rx)
        .map(|key| async move {
            let res = match bucket.get_object(&key).await {
                Ok(res) => res,
                Err(e) => {
                    return Some(Err(e.into()));
                }
            };

            let headers = res.headers();
            let Some(blob_key) = headers.get("x-amz-meta-blob-key") else {
                return None;
            };

            let presigned = bucket.presign_get(blob_key, 3600, None).unwrap();
            Some(Ok::<_, Error>(Message {
                id: key.rsplit('/').next().unwrap().to_string(),
                blob_url: presigned,
                metadata_encrypted: Encrypted(res.to_vec()),
            }))
        })
        .buffer_unordered(PARALLELISM)
        .filter_map(futures::future::ready)
        .try_collect::<Vec<_>>();

    let (results, _) = tokio::try_join!(results_fut, list_fut)?;
    Ok(Json(results))
}

async fn blob(
    Authenticated(domain_key): Authenticated,
    State(state): State<AppState>,
    Path((account, message)): Path<(HashedIdentifier, String)>,
) -> Result<Redirect, Error> {
    let bucket = state.manager.bucket();
    let domain_hash = domain_key.domain_hash();

    let key = InboxKey::prefix(&domain_hash, &account, "_default");

    let res = bucket.get_object(format!("{}{}", key, message)).await?;
    let headers = res.headers();

    let Some(blob_key) = headers.get("x-amz-meta-blob-key") else {
        return Err(Error::NotFound);
    };

    let presigned = bucket.presign_get(blob_key, 3600, None).unwrap();

    Ok(Redirect::temporary(&presigned))
}

async fn domain(
    Query(domain): Query<DomainQuery>,
    State(state): State<AppState>,
) -> Result<Json<DomainKey>, Error> {
    state
        .manager
        .get_domain_key(&domain.domain, true)
        .await?
        .ok_or(Error::NotFound)
        .and_then(DomainKey::try_from)
        .map(Json)
}

async fn me(Authenticated(domain_key): Authenticated) -> Result<Json<DomainKey>, Error> {
    domain_key.try_into().map(Json)
}

async fn metrics(State(state): State<AppState>) -> String {
    state.prometheus.as_ref().unwrap().render()
}

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<Manager>,
    pub prometheus: Option<PrometheusHandle>,
}

pub struct Api {
    pub listener: Listener,
    pub manager: Arc<Manager>,
    pub tls: Option<Arc<TlsProvider>>,
    pub prometheus: Option<PrometheusHandle>,
}

struct Metrics;
impl axum_prometheus::MakeDefaultHandle for Metrics {
    type Out = Metrics;

    fn make_default_handle() -> Self::Out {
        Metrics
    }
}

impl Api {
    pub fn spawn(self, mut shutdown_rx: watch::Receiver<bool>) {
        let mut app = Router::new()
            .route("/healthz", get(healthz))
            .route("/api/v1/me", get(me))
            .route("/api/v1/domain", get(domain))
            .route("/api/v1/directory", get(directory))
            .route("/api/v1/inbox/:account", get(inbox))
            .route("/api/v1/inbox/:account/blob/:message", get(blob))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers(Any)
                    .allow_origin(Any),
            )
            .layer(tower_http::trace::TraceLayer::new_for_http());

        if self.prometheus.is_some() {
            let metric_layer: GenericMetricLayer<Metrics, Metrics> =
                axum_prometheus::MetricLayerBuilder::new()
                    .with_endpoint_label_type(
                        axum_prometheus::EndpointLabel::MatchedPathWithFallbackFn(|_| {
                            "unknown".to_string()
                        }),
                    )
                    .build();
            app = app.route("/metrics", get(metrics)).layer(metric_layer)
        }

        let app = app.with_state(AppState {
            manager: self.manager,
            prometheus: self.prometheus,
        });

        let listener = self.listener.listen();
        let handle = axum_server::Handle::new();

        if let Some(tls) = self.tls {
            let rustls_config = RustlsConfig::from_config(tls.server_config());

            // Spawn TLS refresh loop
            tokio::spawn({
                let rustls_config = rustls_config.clone();
                async move {
                    loop {
                        tls.wait_for_reload().await;
                        rustls_config.reload_from_config(tls.server_config());
                    }
                }
            });

            tokio::spawn(
                axum_server::from_tcp_rustls(listener.into_std().unwrap(), rustls_config)
                    .handle(handle.clone())
                    .serve(app.into_make_service()),
            );
        } else {
            tokio::spawn(
                axum_server::from_tcp(listener.into_std().unwrap())
                    .handle(handle.clone())
                    .serve(app.into_make_service()),
            );
        };

        tokio::spawn(async move {
            shutdown_rx.changed().await.unwrap();
            handle.graceful_shutdown(Some(Duration::from_secs(1)));
        });
    }
}
