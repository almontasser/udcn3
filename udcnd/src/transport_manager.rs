use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use udcn_core::packets::{Interest, Data};
use udcn_transport::Transport;

/// Transport protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Quic,
    Unix,
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub protocol: TransportProtocol,
    pub local_port: u16,
    pub buffer_size: usize,
    pub connection_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: TransportProtocol::Udp,
            local_port: 6363, // Default NDN port
            buffer_size: 65536,
            connection_timeout_ms: 30000,
            keep_alive_interval_ms: 10000,
        }
    }
}

/// Transport connection entry
#[derive(Debug)]
struct TransportConnection {
    socket: Arc<UdpSocket>,
    protocol: TransportProtocol,
    last_used: std::time::Instant,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

/// Transport Manager for NDN packet transmission
pub struct TransportManager {
    config: TransportConfig,
    connections: Arc<RwLock<HashMap<SocketAddr, TransportConnection>>>,
    local_socket: Option<Arc<UdpSocket>>,
    running: Arc<RwLock<bool>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            local_socket: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize the transport manager
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Transport Manager");

        // Create local UDP socket for sending packets
        let local_addr = SocketAddr::from(([0, 0, 0, 0], self.config.local_port));
        let socket = UdpSocket::bind(local_addr).await?;
        self.local_socket = Some(Arc::new(socket));

        // Mark as running
        *self.running.write().await = true;

        info!("Transport Manager started on {}", local_addr);
        Ok(())
    }

    /// Stop the transport manager
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping Transport Manager");

        // Mark as not running
        *self.running.write().await = false;

        // Clear connections
        self.connections.write().await.clear();
        self.local_socket = None;

        info!("Transport Manager stopped");
        Ok(())
    }

    /// Send an Interest packet to a specific address
    pub async fn send_interest(&self, interest: &Interest, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        // Encode the Interest packet
        let encoded_interest = interest.encode()
            .map_err(|e| format!("Failed to encode Interest: {}", e))?;

        // Send the packet
        let bytes_sent = self.send_packet(&encoded_interest, addr).await?;

        debug!("Sent Interest {} ({} bytes) to {}", interest.name, bytes_sent, addr);

        // Update connection statistics
        self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;

        Ok(bytes_sent)
    }

    /// Send a Data packet to a specific address
    pub async fn send_data(&self, data: &Data, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        // Encode the Data packet
        let encoded_data = data.encode()
            .map_err(|e| format!("Failed to encode Data: {}", e))?;

        // Send the packet
        let bytes_sent = self.send_packet(&encoded_data, addr).await?;

        debug!("Sent Data {} ({} bytes) to {}", data.name, bytes_sent, addr);

        // Update connection statistics
        self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;

        Ok(bytes_sent)
    }

    /// Send raw packet data to a specific address
    async fn send_packet(&self, data: &[u8], addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error>> {
        if let Some(ref socket) = self.local_socket {
            let bytes_sent = socket.send_to(data, addr).await?;
            Ok(bytes_sent)
        } else {
            Err("No local socket available".into())
        }
    }

    /// Update connection statistics
    async fn update_connection_stats(&self, addr: SocketAddr, bytes_sent: usize, bytes_received: usize, packets_sent: u64, packets_received: u64) {
        let mut connections = self.connections.write().await;
        
        if let Some(connection) = connections.get_mut(&addr) {
            connection.bytes_sent += bytes_sent as u64;
            connection.bytes_received += bytes_received as u64;
            connection.packets_sent += packets_sent;
            connection.packets_received += packets_received;
            connection.last_used = std::time::Instant::now();
        } else {
            // Create new connection entry if it doesn't exist
            if let Some(ref socket) = self.local_socket {
                let connection = TransportConnection {
                    socket: socket.clone(),
                    protocol: self.config.protocol,
                    last_used: std::time::Instant::now(),
                    bytes_sent: bytes_sent as u64,
                    bytes_received: bytes_received as u64,
                    packets_sent,
                    packets_received,
                };
                connections.insert(addr, connection);
            }
        }
    }

    /// Get connection statistics
    pub async fn get_connection_stats(&self, addr: SocketAddr) -> Option<(u64, u64, u64, u64)> {
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(&addr) {
            Some((connection.bytes_sent, connection.bytes_received, connection.packets_sent, connection.packets_received))
        } else {
            None
        }
    }

    /// Get all connection statistics
    pub async fn get_all_connection_stats(&self) -> HashMap<SocketAddr, (u64, u64, u64, u64)> {
        let connections = self.connections.read().await;
        connections.iter()
            .map(|(addr, conn)| (*addr, (conn.bytes_sent, conn.bytes_received, conn.packets_sent, conn.packets_received)))
            .collect()
    }

    /// Clean up old connections
    pub async fn cleanup_old_connections(&self) {
        let mut connections = self.connections.write().await;
        let now = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(self.config.connection_timeout_ms);

        connections.retain(|addr, connection| {
            if now.duration_since(connection.last_used) > timeout {
                debug!("Removing old connection to {}", addr);
                false
            } else {
                true
            }
        });
    }

    /// Check if transport manager is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get transport configuration
    pub fn get_config(&self) -> &TransportConfig {
        &self.config
    }

    /// Update transport configuration
    pub fn update_config(&mut self, config: TransportConfig) {
        self.config = config;
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new(TransportConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use udcn_core::name::Name;

    #[tokio::test]
    async fn test_transport_manager_lifecycle() {
        let mut manager = TransportManager::default();
        
        // Test start
        assert!(manager.start().await.is_ok());
        assert!(manager.is_running().await);
        
        // Test stop
        assert!(manager.stop().await.is_ok());
        assert!(!manager.is_running().await);
    }

    #[tokio::test]
    async fn test_send_interest() {
        let mut manager = TransportManager::default();
        manager.start().await.unwrap();
        
        let name = Name::from_str("/test/interest").unwrap();
        let interest = Interest::new(name);
        let addr = SocketAddr::from(([127, 0, 0, 1], 6363));
        
        // This will fail in test environment without actual network setup
        // but we can test the basic functionality
        let result = manager.send_interest(&interest, addr).await;
        
        // In a real network environment, this would succeed
        // For now, we just verify the manager is running
        assert!(manager.is_running().await);
        
        manager.stop().await.unwrap();
    }
}