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

use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Instant};

use proxy_header::{io::ProxiedStream, ParseConfig};
use smtp_proto::{
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, RequestReceiver,
    },
    Error as SmtpError, *,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use tracing::Span;

use crate::{
    error::Error,
    manager::Manager,
    smtp::{server::ServerInstance, Address, Configuration, DomainPart, IsTls, SessionManager},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub address_lcase: String,
}

#[derive(Debug)]
pub struct Message {
    pub created: time::OffsetDateTime,

    pub ehlo_domain: String,
    pub return_path: Address,
    pub recipients: Vec<Address>,

    pub body: Vec<u8>,
}

pub enum State {
    Request(RequestReceiver),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    DataTooLarge(DummyDataReceiver),
    RequestTooLarge(DummyLineReceiver),
    Accepted,
    None,
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
    }
}

pub struct SessionData {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub helo_domain: String,

    pub mail_from: Option<Address>,
    pub rcpt_to: Vec<Address>,
    pub rcpt_errors: usize,
    pub message: Vec<u8>,

    pub valid_until: Instant,
    pub bytes_left: usize,
    pub messages_sent: usize,
}

impl SessionData {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16) -> Self {
        SessionData {
            local_ip,
            remote_ip,
            remote_port,
            helo_domain: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            valid_until: Instant::now(),
            rcpt_errors: 0,
            message: Vec::with_capacity(0),
            messages_sent: 0,
            bytes_left: 0,
        }
    }
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub state: State,
    pub manager: Arc<Manager>,
    pub instance: Arc<ServerInstance>,
    pub configuration: Arc<Configuration>,
    pub span: Span,
    pub stream: T,
    pub data: SessionData,
}

impl<T: AsyncWrite + AsyncRead + IsTls + Unpin> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String) -> Result<(), ()> {
        // Set EHLO domain
        self.data.helo_domain = domain;

        let mut response = EhloResponse::new(self.instance.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
        if self.instance.tls.is_some() && !self.stream.is_tls() {
            response.capabilities |= EXT_START_TLS;
        }

        response.capabilities |= EXT_PIPELINING;
        response.capabilities |= EXT_CHUNKING;

        // Require TLS
        if self.configuration.requiretls {
            response.capabilities |= EXT_REQUIRE_TLS;
        }

        // Size
        response.size = self.configuration.max_message_size;
        response.capabilities |= EXT_SIZE;

        // Generate response
        let mut buf = Vec::with_capacity(64);
        response.write(&mut buf).ok();
        self.write(&buf).await
    }

    pub async fn handle_rcpt_to(&mut self, to: RcptTo<String>) -> Result<(), ()> {
        if self.data.mail_from.is_none() {
            return self.write(b"503 5.5.1 MAIL is required first.\r\n").await;
        } else if self.data.rcpt_to.len() >= self.configuration.rcpt_max {
            return self.write(b"451 4.5.3 Too many recipients.\r\n").await;
        }

        // Verify parameters
        if (to.flags
            & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_NEVER | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE)
            != 0)
            || to.orcpt.is_some()
        {
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        // Build RCPT
        let address_lcase = to.address.to_lowercase();
        let rcpt = Address {
            domain: address_lcase.domain_part().to_string(),
            address_lcase,
            address: to.address,
        };

        if self.data.rcpt_to.contains(&rcpt) {
            return self.write(b"250 2.1.5 OK\r\n").await;
        }

        match self.manager.recipient_allowed(&rcpt).await {
            Ok(true) => {
                metrics::counter!("smtp_recepient_verify_total", 1, "outcome" => "accepted");
                tracing::debug!(parent: &self.span,
                    context = "rcpt",
                    event = "success",
                    address = &rcpt.address
                );

                self.data.rcpt_to.push(rcpt);
                self.write(b"250 2.1.5 OK\r\n").await
            }
            Ok(false) => {
                metrics::counter!("smtp_recepient_verify_total", 1, "outcome" => "rejected");
                tracing::debug!(parent: &self.span,
                    context = "rcpt",
                    event = "error",
                    address = &rcpt.address_lcase,
                    "Relay not allowed.");

                self.data.rcpt_to.pop();
                self.rcpt_error(b"550 5.1.2 Relay not allowed.\r\n").await
            }
            Err(e) => {
                metrics::counter!("smtp_recepient_verify_total", 1, "outcome" => "failed");
                tracing::debug!(parent: &self.span,
                    context = "rcpt",
                    event = "error",
                    address = &rcpt.address_lcase,
                    error = ?e,
                    "Temporary address verification failure."
                );

                self.data.rcpt_to.pop();
                self.write(b"451 4.4.3 Unable to verify address at this time.\r\n")
                    .await
            }
        }
    }

    pub async fn handle_mail_from(&mut self, from: MailFrom<String>) -> Result<(), ()> {
        if self.data.helo_domain.is_empty() && self.configuration.ehlo_require {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        }

        let (address, address_lcase, domain) = if !from.address.is_empty() {
            let address_lcase = from.address.to_lowercase();
            let domain = address_lcase.domain_part().to_string();
            (from.address, address_lcase, domain)
        } else {
            (String::new(), String::new(), String::new())
        };

        let has_dsn = from.env_id.is_some();
        self.data.mail_from = Address {
            address,
            address_lcase,
            domain,
        }
        .into();

        // Validate parameters
        if (from.flags & MAIL_REQUIRETLS) != 0 && !self.configuration.requiretls {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 REQUIRETLS has been disabled.\r\n")
                .await;
        }
        if (from.flags & (MAIL_BY_NOTIFY | MAIL_BY_RETURN)) != 0 {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 DELIVERBY extension has been disabled.\r\n")
                .await;
        }
        if from.mt_priority != 0 {
            return self
                .write(b"501 5.5.4 MT-PRIORITY extension has been disabled.\r\n")
                .await;
        }
        if from.size > 0 && from.size > self.configuration.max_message_size {
            self.data.mail_from = None;
            return self
                .write(b"552 5.3.4 Message too big for system.\r\n")
                .await;
        }
        if from.hold_for != 0 || from.hold_until != 0 {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 FUTURERELEASE extension has been disabled.\r\n")
                .await;
        }
        if has_dsn {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        tracing::debug!(parent: &self.span,
            context = "mail-from",
            event = "success",
            address = &self.data.mail_from.as_ref().unwrap().address);

        self.write(b"250 2.1.0 OK\r\n").await
    }

    pub async fn eval_session_params(&mut self) {
        self.data.bytes_left = self.configuration.transfer_limit;
        self.data.valid_until += self.configuration.duration;
    }

    async fn rcpt_error(&mut self, response: &[u8]) -> Result<(), ()> {
        tokio::time::sleep(self.configuration.rcpt_errors_wait).await;
        self.data.rcpt_errors += 1;
        self.write(response).await?;
        if self.data.rcpt_errors < self.configuration.rcpt_errors_max {
            Ok(())
        } else {
            self.write(b"421 4.3.0 Too many errors, disconnecting.\r\n")
                .await?;
            tracing::debug!(
                parent: &self.span,
                context = "rcpt",
                event = "disconnect",
                reason = "too-many-errors",
                "Too many invalid RCPT commands."
            );
            Err(())
        }
    }

    pub async fn queue_message(&mut self) -> Cow<'static, [u8]> {
        let message = Message {
            created: time::OffsetDateTime::now_utc(),

            ehlo_domain: self.data.helo_domain.clone(),
            return_path: self.data.mail_from.clone().unwrap(),
            recipients: std::mem::take(&mut self.data.rcpt_to),
            body: std::mem::take(&mut self.data.message),
        };

        let body_len = message.body.len();
        match self.manager.store_message(message).await {
            Ok(()) => {
                metrics::counter!("smtp_messages_total", 1, "outcome" => "processed");
                tracing::info!(
                    parent: &self.span,
                    context = "data",
                    event = "message",
                    size = body_len,
                    "Message queued for delivery."
                );

                self.state = State::Accepted;
                self.data.messages_sent += 1;

                (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into()
            }
            Err(Error::MalformedMessage) => {
                metrics::counter!("smtp_messages_total", 1, "outcome" => "rejected");
                tracing::info!(parent: &self.span,
                    context = "data",
                    event = "parse-failed",
                    size = body_len
                );

                (&b"550 5.7.7 Failed to parse message.\r\n"[..]).into()
            }
            Err(e) => {
                metrics::counter!("smtp_messages_total", 1, "outcome" => "failed");
                tracing::warn!(
                    parent: &self.span,
                    context = "data",
                    event = "error",
                    error = ?e,
                    "Failed to queue message."
                );

                (b"451 4.3.5 Unable to accept message at this time.\r\n"[..]).into()
            }
        }
    }

    pub async fn can_send_data(&mut self) -> Result<bool, ()> {
        if !self.data.rcpt_to.is_empty() {
            if self.data.messages_sent < self.configuration.max_messages {
                Ok(true)
            } else {
                tracing::debug!(
                    parent: &self.span,
                    context = "data",
                    event = "too-many-messages",
                    "Maximum number of messages per session exceeded."
                );
                self.write(b"451 4.4.5 Maximum number of messages per session exceeded.\r\n")
                    .await?;
                Ok(false)
            }
        } else {
            self.write(b"503 5.5.1 RCPT is required first.\r\n").await?;
            Ok(false)
        }
    }

    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        let mut iter = bytes.iter();
        let mut state = std::mem::replace(&mut self.state, State::None);

        'outer: loop {
            match &mut state {
                State::Request(receiver) => loop {
                    match receiver.ingest(&mut iter, bytes) {
                        Ok(request) => match request {
                            Request::Rcpt { to } => {
                                self.handle_rcpt_to(to).await?;
                            }
                            Request::Mail { from } => {
                                self.handle_mail_from(from).await?;
                            }
                            Request::Ehlo { host } => {
                                self.handle_ehlo(host).await?;
                            }
                            Request::Data => {
                                if self.can_send_data().await? {
                                    self.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                        .await?;
                                    self.data.message = Vec::with_capacity(1024);
                                    state = State::Data(DataReceiver::new());
                                    continue 'outer;
                                }
                            }
                            Request::Bdat {
                                chunk_size,
                                is_last,
                            } => {
                                state = if chunk_size + self.data.message.len()
                                    < self.configuration.max_message_size
                                {
                                    if self.data.message.is_empty() {
                                        self.data.message = Vec::with_capacity(chunk_size);
                                    } else {
                                        self.data.message.reserve(chunk_size);
                                    }
                                    State::Bdat(BdatReceiver::new(chunk_size, is_last))
                                } else {
                                    // Chunk is too large, ignore.
                                    State::DataTooLarge(DummyDataReceiver::new_bdat(chunk_size))
                                };
                                continue 'outer;
                            }
                            Request::Auth { .. } => {
                                self.write(b"503 5.5.1 AUTH not allowed.\r\n").await?;
                            }
                            Request::Noop { .. } => {
                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Vrfy { .. } => {
                                self.write(b"252 2.5.1 VRFY is disabled.\r\n").await?;
                            }
                            Request::Expn { .. } => {
                                self.write(b"252 2.5.1 EXPN is disabled.\r\n").await?;
                            }
                            Request::StartTls => {
                                if self.instance.tls.is_none() {
                                    self.write(b"502 5.5.1 Command not implemented.\r\n")
                                        .await?;
                                } else if !self.stream.is_tls() {
                                    self.write(b"220 2.0.0 Ready to start TLS.\r\n").await?;
                                    self.state = State::default();
                                    return Ok(false);
                                } else {
                                    self.write(b"504 5.7.4 Already in TLS mode.\r\n").await?;
                                }
                            }
                            Request::Rset => {
                                self.reset();
                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Quit => {
                                self.write(b"221 2.0.0 Bye.\r\n").await?;
                                return Err(());
                            }
                            Request::Help { .. } => {
                                self.write(
                                    b"250 2.0.0 Help can often be found in the least expected places\r\n",
                                )
                                .await?;
                            }
                            Request::Helo { host } => {
                                self.data.helo_domain = host;
                                self.write(
                                    format!("250 {} says hello\r\n", self.instance.hostname)
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Request::Lhlo { .. } => {
                                self.write(b"502 5.5.1 Invalid command.\r\n").await?;
                            }
                            Request::Etrn { .. } | Request::Atrn { .. } | Request::Burl { .. } => {
                                self.write(b"502 5.5.1 Command not implemented.\r\n")
                                    .await?;
                            }
                        },
                        Err(err) => match err {
                            SmtpError::NeedsMoreData { .. } => break 'outer,
                            SmtpError::UnknownCommand | SmtpError::InvalidResponse { .. } => {
                                self.write(b"500 5.5.1 Invalid command.\r\n").await?;
                            }
                            SmtpError::InvalidSenderAddress => {
                                self.write(b"501 5.1.8 Bad sender's system address.\r\n")
                                    .await?;
                            }
                            SmtpError::InvalidRecipientAddress => {
                                self.write(
                                    b"501 5.1.3 Bad destination mailbox address syntax.\r\n",
                                )
                                .await?;
                            }
                            SmtpError::SyntaxError { syntax } => {
                                self.write(
                                    format!("501 5.5.2 Syntax error, expected: {syntax}\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            SmtpError::InvalidParameter { param } => {
                                self.write(
                                    format!("501 5.5.4 Invalid parameter {param:?}.\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            SmtpError::UnsupportedParameter { param } => {
                                self.write(
                                    format!("504 5.5.4 Unsupported parameter {param:?}.\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            SmtpError::ResponseTooLong => {
                                state = State::RequestTooLarge(DummyLineReceiver::default());
                                continue 'outer;
                            }
                        },
                    }
                },
                State::Data(receiver) => {
                    if self.data.message.len() + bytes.len() < self.configuration.max_message_size {
                        if receiver.ingest(&mut iter, &mut self.data.message) {
                            let message = self.queue_message().await;
                            if !message.is_empty() {
                                self.write(message.as_ref()).await?;
                                self.reset();
                                state = State::default();
                            } else {
                                // Disconnect requested
                                return Err(());
                            }
                        } else {
                            break 'outer;
                        }
                    } else {
                        state = State::DataTooLarge(DummyDataReceiver::new_data(receiver));
                    }
                }
                State::Bdat(receiver) => {
                    if receiver.ingest(&mut iter, &mut self.data.message) {
                        if self.can_send_data().await? {
                            if receiver.is_last {
                                let message = self.queue_message().await;
                                if !message.is_empty() {
                                    self.write(message.as_ref()).await?;
                                    self.reset();
                                } else {
                                    // Disconnect requested
                                    return Err(());
                                }
                            } else {
                                self.write(b"250 2.6.0 Chunk accepted.\r\n").await?;
                            }
                        } else {
                            self.data.message = Vec::with_capacity(0);
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::DataTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        tracing::debug!(
                            parent: &self.span,
                            context = "data",
                            event = "too-large",
                            "Message is too large."
                        );

                        self.data.message = Vec::with_capacity(0);
                        self.write(b"552 5.3.4 Message too big for system.\r\n")
                            .await?;
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::RequestTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        self.write(b"554 5.3.4 Line is too long.\r\n").await?;
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::None | State::Accepted => unreachable!(),
            }
        }
        self.state = state;

        Ok(true)
    }

    async fn init_conn(&mut self) -> bool {
        self.eval_session_params().await;

        let instance = self.instance.clone();
        if self.write(instance.data.as_bytes()).await.is_err() {
            return false;
        }

        true
    }

    async fn handle_conn_(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    self.configuration.timeout,
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    if Instant::now() < self.data.valid_until && bytes_read <= self.data.bytes_left  {
                                        self.data.bytes_left -= bytes_read;
                                        match self.ingest(&buf[..bytes_read]).await {
                                            Ok(true) => (),
                                            Ok(false) => {
                                                return true;
                                            }
                                            Err(_) => {
                                                break;
                                            }
                                        }
                                    } else if bytes_read > self.data.bytes_left {
                                        self
                                            .write(format!("451 4.7.28 {} Session exceeded transfer quota.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "transfer-limit",
                                            "Client exceeded incoming transfer limit."
                                        );
                                        break;
                                    } else {
                                        self
                                            .write(format!("453 4.3.2 {} Session open for too long.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "loiter",
                                            "Session open for too long."
                                        );
                                        break;
                                    }
                                } else {
                                    tracing::debug!(
                                        parent: &self.span,
                                        event = "disconnect",
                                        reason = "peer",
                                        "Connection closed by peer."
                                    );
                                    break;
                                }
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    parent: &self.span,
                                    event = "disconnect",
                                    reason = "timeout",
                                    "Connection timed out."
                                );
                                self
                                    .write(format!("221 2.0.0 {} Disconnecting inactive client.\r\n", self.instance.hostname).as_bytes())
                                    .await
                                    .ok();
                                break;
                            }
                        }
                },
                _ = shutdown_rx.changed() => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        reason = "shutdown",
                        "Server shutting down."
                    );
                    self.write(b"421 4.3.0 Server shutting down.\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }

    pub fn reset(&mut self) {
        self.data.mail_from = None;
        self.data.rcpt_to.clear();
        self.data.message = Vec::with_capacity(0);
    }

    #[inline(always)]
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let err = match self.stream.write_all(bytes).await {
            Ok(_) => match self.stream.flush().await {
                Ok(_) => {
                    tracing::trace!(parent: &self.span,
                            event = "write",
                            data = std::str::from_utf8(bytes).unwrap_or_default() ,
                            size = bytes.len());
                    return Ok(());
                }
                Err(err) => err,
            },
            Err(err) => err,
        };

        tracing::debug!(parent: &self.span,
            event = "error",
            "Failed to write to stream: {:?}", err);
        Err(())
    }

    #[inline(always)]
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        match self.stream.read(bytes).await {
            Ok(len) => {
                tracing::trace!(parent: &self.span,
                                event = "read",
                                data =  if matches!(self.state, State::Request(_)) {bytes
                                    .get(0..len)
                                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                    .unwrap_or("[invalid UTF8]")} else {"[DATA]"},
                                size = len);
                Ok(len)
            }
            Err(err) => {
                tracing::debug!(
                    parent: &self.span,
                    event = "error",
                    "Failed to read from stream: {:?}", err
                );
                Err(())
            }
        }
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        let span = self.span;
        Ok(Session {
            stream: self.instance.tls_accept(self.stream, &span).await?,
            state: self.state,
            data: self.data,
            manager: self.manager,
            configuration: self.configuration,
            instance: self.instance,
            span,
        })
    }
}

impl Session<ProxiedStream<TcpStream>> {
    pub async fn handle_conn(mut self) {
        if self.handle_conn_().await && self.instance.tls.is_some() {
            if let Ok(session) = self.into_tls().await {
                session.handle_conn().await;
            }
        }
    }
}

impl Session<TlsStream<ProxiedStream<TcpStream>>> {
    pub async fn handle_conn(mut self) {
        self.handle_conn_().await;
    }
}

#[derive(Clone)]
pub struct SmtpSessionManager {
    pub configuration: Arc<Configuration>,
    pub manager: Arc<Manager>,
    pub proxy_protocol: bool,
}

impl SessionManager for SmtpSessionManager {
    fn spawn(&self, session: super::server::SessionData<TcpStream>) {
        metrics::counter!("smtp_sessions_total", 1);

        // Create session
        let configuration = self.configuration.clone();
        let manager = self.manager.clone();

        let use_proxy_protocol = self.proxy_protocol;

        tokio::spawn(async move {
            let mut session_data =
                SessionData::new(session.local_ip, session.remote_ip, session.remote_port);
            let mut span = session.span;

            let stream = if use_proxy_protocol {
                match tokio::time::timeout(
                    configuration.timeout,
                    ProxiedStream::create_from_tokio(
                        session.stream,
                        ParseConfig {
                            include_tlvs: true,
                            ..Default::default()
                        },
                    ),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        let header = stream.proxy_header();
                        tracing::debug! {
                            parent: &span,
                            context = "tcp",
                            event = "proxy_header",
                            header = ?header,
                            "Received proxy header."
                        };

                        if let Some(addr_info) = header.proxied_address() {
                            session_data.local_ip = addr_info.destination.ip();
                            session_data.remote_ip = addr_info.source.ip();
                            session_data.remote_port = addr_info.source.port();
                            span = tracing::info_span!(
                                "session",
                                instance = session.instance.id,
                                remote.ip = addr_info.source.ip().to_string(),
                                remote.port = addr_info.source.port()
                            );
                        }

                        stream
                    }
                    Ok(_) => {
                        tracing::debug!(
                            parent: &span,
                            context = "tcp",
                            event = "error",
                            "Failed to parse proxy header."
                        );
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(
                            parent: &span,
                            event = "disconnect",
                            reason = "timeout",
                            "Connection timed out."
                        );
                        return;
                    }
                }
            } else {
                ProxiedStream::unproxied(session.stream)
            };

            let mut session = Session {
                configuration,
                instance: session.instance,
                manager,
                state: State::default(),
                span,
                stream,
                data: session_data,
            };

            if session.init_conn().await {
                session.handle_conn().await;
            }

            metrics::increment_gauge!("smtp_sessions_active", -1.0);
        });
    }

    fn shutdown(&self) {}
}
