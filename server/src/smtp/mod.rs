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

pub mod server;
pub mod session;

use std::time::Duration;

use proxy_header::io::ProxiedStream;
use std::hash::Hash;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

#[derive(Debug)]
pub struct Configuration {
    pub max_message_size: usize,
    pub max_messages: usize,
    pub requiretls: bool,
    pub rcpt_max: usize,
    pub duration: Duration,
    pub timeout: Duration,

    pub transfer_limit: usize,

    // Ehlo parameters
    pub ehlo_require: bool,
    pub ehlo_reject_non_fqdn: bool,

    // Rcpt parameters
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            max_message_size: 25 * 1024 * 1024,
            max_messages: 10,
            requiretls: false,
            rcpt_max: 25,
            duration: Duration::from_secs(600),
            timeout: Duration::from_secs(300),
            transfer_limit: 250 * 1024 * 1024,
            ehlo_require: true,
            ehlo_reject_non_fqdn: true,
            rcpt_errors_max: 5,
            rcpt_errors_wait: Duration::from_secs(5),
        }
    }
}

pub trait DomainPart {
    fn domain_part(&self) -> &str;
}

impl DomainPart for &str {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

impl DomainPart for String {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct Address {
    pub address: String,
    pub address_lcase: String,
    pub domain: String,
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.address_lcase == other.address_lcase
    }
}

impl Eq for Address {}

impl Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address_lcase.hash(state);
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.domain.cmp(&other.domain) {
            std::cmp::Ordering::Equal => self.address_lcase.cmp(&other.address_lcase),
            order => order,
        }
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub trait IsTls {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (&'static str, &'static str);
}

impl IsTls for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }
    fn tls_version_and_cipher(&self) -> (&'static str, &'static str) {
        ("", "")
    }
}

impl IsTls for ProxiedStream<TcpStream> {
    fn is_tls(&self) -> bool {
        false
    }
    fn tls_version_and_cipher(&self) -> (&'static str, &'static str) {
        ("", "")
    }
}

impl<T> IsTls for TlsStream<T> {
    fn is_tls(&self) -> bool {
        true
    }

    fn tls_version_and_cipher(&self) -> (&'static str, &'static str) {
        let (_, conn) = self.get_ref();

        (
            match conn
                .protocol_version()
                .unwrap_or(rustls::ProtocolVersion::Unknown(0))
            {
                rustls::ProtocolVersion::SSLv2 => "SSLv2",
                rustls::ProtocolVersion::SSLv3 => "SSLv3",
                rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0",
                rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1",
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
                rustls::ProtocolVersion::DTLSv1_0 => "DTLSv1.0",
                rustls::ProtocolVersion::DTLSv1_2 => "DTLSv1.2",
                rustls::ProtocolVersion::DTLSv1_3 => "DTLSv1.3",
                _ => "unknown",
            },
            match conn.negotiated_cipher_suite() {
                Some(rustls::SupportedCipherSuite::Tls13(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                Some(rustls::SupportedCipherSuite::Tls12(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                None => "unknown",
            },
        )
    }
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn(&self, session: self::server::SessionData<TcpStream>);
    fn shutdown(&self);
}
