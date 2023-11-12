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

use std::{net::SocketAddr, time::Duration};
use tokio::net::{TcpListener, TcpSocket};

#[derive(Debug)]
pub struct Listener {
    pub socket: TcpSocket,
    pub addr: SocketAddr,
    pub backlog: Option<u32>,

    // TCP options
    pub ttl: Option<u32>,
    pub linger: Option<Duration>,
    pub nodelay: bool,
}

impl Listener {
    pub fn create(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }?;

        socket.set_reuseaddr(true)?;
        socket.set_reuseport(true)?;

        Ok(Self {
            socket,
            addr,
            backlog: Some(1024),
            ttl: None,
            linger: None,
            nodelay: true,
        })
    }

    pub fn listen(self) -> TcpListener {
        self.socket
            .listen(self.backlog.unwrap_or(1024))
            .unwrap_or_else(|err| panic!("Failed to listen on {}: {}", self.addr, err))
    }
}
