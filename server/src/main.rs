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

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use api::Api;
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;

use listener::Listener;
use metrics_exporter_prometheus::PrometheusBuilder;
use tls::TlsProvider;

mod api;
mod error;
mod listener;
mod manager;
mod smtp;
mod tls;
mod utils;

use crate::{error::Result, manager::Manager};

use s3::creds::Credentials;
use smtp::{server::SmtpServer, session::SmtpSessionManager};
use tracing_subscriber::EnvFilter;
use utils::wait_for_shutdown_signal;

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// SMTP bind address
    #[clap(long, default_value = "[::]:25")]
    smtp_bind: SocketAddr,

    /// HTTP API bind address
    #[clap(long, default_value = "[::]:80")]
    api_bind: SocketAddr,

    /// SMTP TLS certificate path
    #[clap(long)]
    smtp_tls_cert: Option<PathBuf>,

    /// SMTP TLS key path
    #[clap(long)]
    smtp_tls_key: Option<PathBuf>,

    /// HTTP API TLS certificate path
    #[clap(long)]
    api_tls_cert: Option<PathBuf>,

    /// HTTP API TLS key path
    #[clap(long)]
    api_tls_key: Option<PathBuf>,

    /// How often to reload TLS certificates (in seconds)
    #[clap(long, default_value = "600")]
    tls_reload_interval: u64,

    /// Hostname
    #[clap(long, default_value = "localhost")]
    hostname: String,

    /// Use HAProxy PROXY protocol for SMTP
    #[clap(long)]
    proxy_protocol: bool,

    /// S3 bucket name
    #[clap(long)]
    bucket_name: String,

    /// S3 bucket region
    #[clap(long)]
    bucket_region: String,

    /// S3 bucket endpoint URL (for S3-compatible storage)
    #[clap(long)]
    bucket_endpoint: Option<String>,

    /// Check configuration and exit
    #[clap(long)]
    check: bool,

    /// Enable Prometheus metrics
    #[clap(long)]
    prometheus: bool,
}

async fn run(args: Args) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let s3_creds = Credentials::default()?;
    let s3_region = s3::Region::Custom {
        region: args.bucket_region.clone(),
        endpoint: args
            .bucket_endpoint
            .unwrap_or_else(|| format!("s3.dualstack.{}.amazonaws.com", args.bucket_region)),
    };

    let bucket = *s3::Bucket::new(&args.bucket_name, s3_region, s3_creds)?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let manager = Arc::new(Manager::new(resolver, bucket));

    let session_manager = SmtpSessionManager {
        configuration: Default::default(),
        manager: manager.clone(),
        proxy_protocol: args.proxy_protocol,
    };

    let smtp_tls =
        TlsProvider::create_from_paths(args.smtp_tls_cert, args.smtp_tls_key)?.map(Arc::new);
    let server = SmtpServer {
        id: args.hostname.clone(),
        hostname: args.hostname,
        data: "Compost SMTP Server".to_string(),
        listeners: vec![Listener::create(args.smtp_bind)?],
        tls: smtp_tls.clone(),
    };

    for listener in &server.listeners {
        listener.socket.bind(listener.addr)?;
    }

    let prometheus = args
        .prometheus
        .then(|| PrometheusBuilder::new().install_recorder().unwrap());

    let api_tls =
        TlsProvider::create_from_paths(args.api_tls_cert, args.api_tls_key)?.map(Arc::new);
    let api = Api {
        listener: Listener::create(args.api_bind)?,
        manager: manager.clone(),
        tls: api_tls.clone(),
        prometheus,
    };

    let tls_reload_interval = Duration::from_secs(args.tls_reload_interval);

    if args.check {
        return Ok(());
    }

    if let Some(tls) = smtp_tls {
        tokio::spawn(tls.run_reload_loop(tls_reload_interval, shutdown_rx.clone()));
    }
    if let Some(tls) = api_tls {
        tokio::spawn(tls.run_reload_loop(tls_reload_interval, shutdown_rx.clone()));
    }

    api.listener.socket.bind(api.listener.addr)?;

    server.spawn(session_manager, shutdown_rx.clone());
    api.spawn(shutdown_rx);

    wait_for_shutdown_signal().await?;

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let stdout = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("LOG_LEVEL"))
        .finish();

    tracing::subscriber::set_global_default(stdout).unwrap();

    match run(args).await {
        Ok(()) => {}
        Err(err) => {
            tracing::error!(
                error = ?err,
                "Error during execution"
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
