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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("AWS credentials error: {0}")]
    Credentials(#[from] s3::creds::error::CredentialsError),
    #[error("S3 error: {0}")]
    S3(#[from] s3::error::S3Error),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Resolver error: {0}")]
    Resolver(#[from] hickory_resolver::error::ResolveError),

    #[error("Invalid domain key")]
    InvalidDomainKey,
    #[error("Invalid recepient")]
    InvalidRecepient,
    #[error("Malformed message")]
    MalformedMessage,

    #[error("Not found")]
    NotFound,

    #[error("Join error")]
    JoinError(#[from] tokio::task::JoinError),

    #[allow(dead_code)]
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
