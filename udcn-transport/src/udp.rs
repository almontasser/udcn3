use std::net::SocketAddr;
use tokio::net::UdpSocket;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::{Transport, AsyncTransport, ConcurrentTransport, TransportStats};

#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<Mutex<Option<tokio::net::UdpSocket>>>,
    peer_addr: Arc<Mutex<Option<std::net::SocketAddr>>>,
    stats: Arc<Mutex<TransportStats>>,
}

impl UdpTransport {
    pub fn new() -> Self {
        Self {
            socket: Arc::new(Mutex::new(None)),
            peer_addr: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(TransportStats::default())),
        }
    }

    /// Create a new UDP transport bound to the specified address
    pub async fn new_bound(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: Arc::new(Mutex::new(Some(socket))),
            peer_addr: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(TransportStats::default())),
        })
    }

    pub async fn bind(&mut self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        *self.socket.lock().await = Some(socket);
        Ok(())
    }

    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        *self.peer_addr.lock().await = Some(addr);
        Ok(())
    }

    pub async fn local_addr(&self) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let socket_guard = self.socket.lock().await;
        if let Some(ref socket) = *socket_guard {
            Ok(socket.local_addr()?)
        } else {
            Err("Not bound".into())
        }
    }
}

impl Transport for UdpTransport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Use blocking runtime for sync API
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let socket_guard = self.socket.lock().await;
            let addr_guard = self.peer_addr.lock().await;
            if let (Some(ref socket), Some(ref addr)) = (&*socket_guard, &*addr_guard) {
                socket.send_to(data, addr).await?;
                Ok(())
            } else {
                Err("Not connected".into())
            }
        })
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Use blocking runtime for sync API
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let socket_guard = self.socket.lock().await;
            if let Some(ref socket) = &*socket_guard {
                let mut buffer = vec![0; 1024];
                let (bytes_read, _) = socket.recv_from(&mut buffer).await?;
                buffer.truncate(bytes_read);
                Ok(buffer)
            } else {
                Err("Not bound".into())
            }
        })
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

impl Default for UdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AsyncTransport for UdpTransport {
    async fn send_async(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket_guard = self.socket.lock().await;
        let addr_guard = self.peer_addr.lock().await;
        if let (Some(ref socket), Some(ref addr)) = (&*socket_guard, &*addr_guard) {
            match socket.send_to(data, addr).await {
                Ok(_) => {
                    let mut stats = self.stats.lock().await;
                    stats.bytes_sent += data.len() as u64;
                    stats.packets_sent += 1;
                    stats.last_activity = Some(std::time::Instant::now());
                    Ok(())
                }
                Err(e) => {
                    let mut stats = self.stats.lock().await;
                    stats.send_errors += 1;
                    Err(e.into())
                }
            }
        } else {
            Err("Not connected".into())
        }
    }

    async fn receive_async(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket_guard = self.socket.lock().await;
        if let Some(ref socket) = &*socket_guard {
            let mut buffer = vec![0; 1024];
            match socket.recv_from(&mut buffer).await {
                Ok((bytes_read, _)) => {
                    buffer.truncate(bytes_read);
                    let mut stats = self.stats.lock().await;
                    stats.bytes_received += bytes_read as u64;
                    stats.packets_received += 1;
                    stats.last_activity = Some(std::time::Instant::now());
                    Ok(buffer)
                }
                Err(e) => {
                    let mut stats = self.stats.lock().await;
                    stats.receive_errors += 1;
                    Err(e.into())
                }
            }
        } else {
            Err("Not bound".into())
        }
    }

    async fn close_async(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn send_to_async(&self, data: &[u8], addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket_guard = self.socket.lock().await;
        if let Some(ref socket) = &*socket_guard {
            match socket.send_to(data, addr).await {
                Ok(_) => {
                    let mut stats = self.stats.lock().await;
                    stats.bytes_sent += data.len() as u64;
                    stats.packets_sent += 1;
                    stats.last_activity = Some(std::time::Instant::now());
                    Ok(())
                }
                Err(e) => {
                    let mut stats = self.stats.lock().await;
                    stats.send_errors += 1;
                    Err(e.into())
                }
            }
        } else {
            Err("Not bound".into())
        }
    }

    async fn receive_timeout_async(&self, timeout: std::time::Duration) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let socket_guard = self.socket.lock().await;
        if let Some(ref socket) = &*socket_guard {
            let mut buffer = vec![0; 1024];
            match tokio::time::timeout(timeout, socket.recv_from(&mut buffer)).await {
                Ok(Ok((bytes_read, _))) => {
                    buffer.truncate(bytes_read);
                    let mut stats = self.stats.lock().await;
                    stats.bytes_received += bytes_read as u64;
                    stats.packets_received += 1;
                    stats.last_activity = Some(std::time::Instant::now());
                    Ok(buffer)
                }
                Ok(Err(e)) => {
                    let mut stats = self.stats.lock().await;
                    stats.receive_errors += 1;
                    Err(e.into())
                }
                Err(e) => Err(e.into())
            }
        } else {
            Err("Not bound".into())
        }
    }
}

impl ConcurrentTransport for UdpTransport {
    fn get_stats(&self) -> TransportStats {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.stats.lock().await.clone()
        })
    }

    fn reset_stats(&self) {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            *self.stats.lock().await = TransportStats::default();
        });
    }
}
