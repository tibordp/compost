/*
 * Adapted from Stalwart Mail Server, which is available on
 * https://github.com/stalwartlabs/mail-server/
 *
 * and carries the following license notice:
 *
 * Copyright (c) 2023 Stalwart Labs Ltd.
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
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{net::IpAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::Span;

use crate::{listener::Listener, tls::TlsProvider};

use super::SessionManager;

pub struct SessionData<T: AsyncRead + AsyncWrite + Unpin + 'static> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub span: tracing::Span,
    pub instance: Arc<ServerInstance>,
}

#[derive(Debug, Default)]
pub struct SmtpServer {
    pub id: String,
    pub hostname: String,
    pub data: String,
    pub listeners: Vec<Listener>,
    pub tls: Option<Arc<TlsProvider>>,
    pub max_connections: u64,
}

impl SmtpServer {
    pub fn spawn(self, manager: impl SessionManager, shutdown_rx: watch::Receiver<bool>) {
        // Prepare instance
        let instance = Arc::new(ServerInstance {
            data: format!("220 {} {}\r\n", self.hostname, self.data),
            id: self.id,
            hostname: self.hostname,
            tls: self.tls,
            shutdown_rx,
        });

        // Spawn listeners
        for listener in self.listeners {
            tracing::info!(
                id = instance.id,
                bind.ip = listener.addr.ip().to_string(),
                bind.port = listener.addr.port(),
                "Starting listener"
            );
            let local_ip = listener.addr.ip();

            // Obtain TCP options
            let nodelay = listener.nodelay;
            let ttl = listener.ttl;
            let linger = listener.linger;

            // Bind socket
            let listener = listener.listen();

            // Spawn listener
            let mut shutdown_rx = instance.shutdown_rx.clone();
            let manager = manager.clone();
            let instance = instance.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    metrics::increment_gauge!("smtp_sessions_active", 1.0);

                                    // Convert mapped IPv6 addresses to IPv4
                                    let remote_ip = match remote_addr.ip() {
                                        IpAddr::V6(ip) => {
                                            ip.to_ipv4_mapped()
                                            .map(IpAddr::V4)
                                            .unwrap_or(IpAddr::V6(ip))
                                        }
                                        remote_ip => remote_ip,
                                    };
                                    let remote_port = remote_addr.port();

                                        let span = tracing::info_span!(
                                            "session",
                                            instance = instance.id,
                                            remote.ip = remote_ip.to_string(),
                                            remote.port = remote_port,
                                        );

                                        // Set TCP options
                                        if let Err(err) = stream.set_nodelay(nodelay) {
                                            tracing::warn!(
                                                context = "tcp",
                                                event = "error",
                                                instance = instance.id,

                                                "Failed to set no-delay: {}", err);
                                        }
                                        if let Some(ttl) = ttl {
                                            if let Err(err) = stream.set_ttl(ttl) {
                                                tracing::warn!(
                                                    context = "tcp",
                                                    event = "error",
                                                    instance = instance.id,
                                                    "Failed to set TTL: {}", err);
                                            }
                                        }
                                        if linger.is_some() {
                                            if let Err(err) = stream.set_linger(linger) {
                                                tracing::warn!(
                                                    context = "tcp",
                                                    event = "error",
                                                    instance = instance.id,
                                                    "Failed to set linger: {}", err);
                                            }
                                        }

                                        // Spawn connection
                                        manager.spawn(SessionData {
                                            stream,
                                            local_ip,
                                            remote_ip,
                                            remote_port,
                                            span,
                                            instance: instance.clone(),
                                        });

                                }
                                Err(err) => {
                                    tracing::debug!(context = "io",
                                                    event = "error",
                                                    instance = instance.id,
                                                    "Failed to accept TCP connection: {}", err);
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(
                                event = "shutdown",
                                instance = instance.id,
                                "Listener shutting down.");
                            manager.shutdown();
                            break;
                        }
                    };
                }
            });
        }
    }
}

pub struct ServerInstance {
    pub id: String,
    pub hostname: String,
    pub data: String,
    pub tls: Option<Arc<TlsProvider>>,
    pub shutdown_rx: watch::Receiver<bool>,
}

impl ServerInstance {
    pub async fn tls_accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        span: &Span,
    ) -> Result<TlsStream<S>, ()> {
        let acceptor = TlsAcceptor::from(self.tls.as_ref().unwrap().server_config());

        match acceptor.accept(stream).await {
            Ok(stream) => {
                tracing::info!(
                    parent: span,
                    context = "tls",
                    event = "handshake",
                    version = ?stream.get_ref().1.protocol_version().unwrap_or(rustls::ProtocolVersion::TLSv1_3),
                    cipher = ?stream.get_ref().1.negotiated_cipher_suite().unwrap_or(rustls::cipher_suite::TLS13_AES_128_GCM_SHA256),
                );
                Ok(stream)
            }
            Err(err) => {
                tracing::debug!(
                    parent: span,
                    context = "tls",
                    event = "error",
                    "Failed to accept TLS connection: {}",
                    err
                );
                Err(())
            }
        }
    }
}
