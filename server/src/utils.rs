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

use crate::error::Result;

/// Wait for SIGTERM or SIGINT
pub async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut h_term = signal(SignalKind::terminate())?;
    let mut h_int = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = h_term.recv() => tracing::debug!("Received SIGTERM."),
        _ = h_int.recv() => tracing::debug!("Received SIGINT."),
    };

    Ok(())
}

pub(crate) fn trim_ascii_whitespace(mut part: &[u8]) -> &[u8] {
    while part.first().is_some_and(u8::is_ascii_whitespace) {
        part = &part[1..];
    }

    while part.last().is_some_and(u8::is_ascii_whitespace) {
        part = &part[..part.len() - 1];
    }

    part
}
