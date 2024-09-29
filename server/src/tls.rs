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

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use rustls::ServerConfig;

use crate::error::Error;

#[derive(Debug)]
pub struct TlsProvider {
    config: ArcSwap<rustls::ServerConfig>,
    certificate_path: PathBuf,
    key_path: PathBuf,
    tx: tokio::sync::watch::Sender<()>,
}

impl TlsProvider {
    /// Create a TLS provider from the given certificate and key paths, if specified.
    pub fn create_from_paths(
        tls_cert: Option<PathBuf>,
        tls_key: Option<PathBuf>,
    ) -> Result<Option<Self>, Error> {
        let (certificate, key) = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => (cert, key),
            (None, None) => return Ok(None),
            _ => {
                return Err(Error::InvalidConfiguration(
                    "Both TLS certificate and key must be specified, or neither".into(),
                ))
            }
        };

        let initial_config = create_server_config(&certificate, &key)?;
        let (tx, _) = tokio::sync::watch::channel(());

        Ok(Some(Self {
            config: ArcSwap::new(Arc::new(initial_config)),
            certificate_path: certificate,
            key_path: key,
            tx,
        }))
    }

    /// Refresh the TLS configuration from the certificate and key paths.
    pub fn reload(&self) {
        match create_server_config(&self.certificate_path, &self.key_path) {
            Ok(config) => {
                tracing::debug!("TLS configuration refreshed");
                self.config.store(Arc::new(config));

                // Notify subscribers
                self.tx.send_replace(());
            }
            Err(e) => {
                tracing::error!(
                    event = "tls_refresh_failed",
                    "Failed to refresh TLS configuration: {}",
                    e
                );
            }
        }
    }

    /// Subscribe to TLS configuration refreshes.
    ///
    /// This method returns a watch receiver that will be notified when the TLS configuration
    pub async fn wait_for_reload(&self) {
        let mut rx = self.tx.subscribe();

        let _ = rx.changed().await;
    }

    pub async fn run_reload_loop(
        self: Arc<Self>,
        interval: Duration,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.reload();
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    }

    /// Return the current TLS configuration.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }
}

fn create_server_config(certificate: &Path, key: &Path) -> Result<ServerConfig, Error> {
    let chain = rustls_pemfile::certs(&mut BufReader::new(File::open(certificate)?))
        .collect::<Result<_, _>>()?;

    let key = rustls_pemfile::read_all(&mut BufReader::new(File::open(key)?))
        .filter_map(|key| match key {
            Ok(rustls_pemfile::Item::Pkcs1Key(key)) => Some(Ok(key.into())),
            Ok(rustls_pemfile::Item::Pkcs8Key(key)) => Some(Ok(key.into())),
            Ok(rustls_pemfile::Item::Sec1Key(key)) => Some(Ok(key.into())),
            Err(e) => Some(Err(e)),
            _ => None,
        })
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No private key found"))??;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;

    Ok(config)
}
