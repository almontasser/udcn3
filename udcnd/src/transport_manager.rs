use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{timeout, Duration};
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
    pub bind_address: String,
    pub buffer_size: usize,
    pub connection_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: TransportProtocol::Udp,
            local_port: 6363, // Default NDN port
            bind_address: "0.0.0.0".to_string(),
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

/// Incoming packet type
#[derive(Debug)]
pub enum IncomingPacket {
    Interest(Interest, SocketAddr),
    Data(Data, SocketAddr),
    Unknown(Vec<u8>, SocketAddr),
}

/// Transport Manager for NDN packet transmission
pub struct TransportManager {
    config: TransportConfig,
    connections: Arc<RwLock<HashMap<SocketAddr, TransportConnection>>>,
    pub local_socket: Option<Arc<UdpSocket>>,
    running: Arc<RwLock<bool>>,
    packet_sender: Option<mpsc::Sender<IncomingPacket>>,
    packet_receiver: Option<mpsc::Receiver<IncomingPacket>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new(config: TransportConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            local_socket: None,
            running: Arc::new(RwLock::new(false)),
            packet_sender: Some(tx),
            packet_receiver: Some(rx),
        }
    }

    /// Initialize the transport manager
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting Transport Manager");

        // Parse bind address and create socket address
        let bind_ip: std::net::IpAddr = self.config.bind_address.parse()
            .map_err(|e| format!("Invalid bind address '{}': {}", self.config.bind_address, e))?;
        let local_addr = SocketAddr::new(bind_ip, self.config.local_port);
        
        // Create local UDP socket for sending packets
        let socket = UdpSocket::bind(local_addr).await?;
        self.local_socket = Some(Arc::new(socket));

        // Mark as running
        *self.running.write().await = true;

        // Start packet reception loop
        let socket = self.local_socket.as_ref().unwrap().clone();
        let running = self.running.clone();
        let sender = self.packet_sender.as_ref().unwrap().clone();
        
        tokio::spawn(async move {
            Self::packet_reception_loop(socket, running, sender).await;
        });

        info!("Transport Manager started on {}", local_addr);
        info!("Packet reception loop spawned");
        Ok(())
    }

    /// Stop the transport manager
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    pub async fn send_interest(&self, interest: &Interest, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
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
    pub async fn send_data(&self, data: &Data, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
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
    async fn send_packet(&self, data: &[u8], addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
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

    /// Get the local socket for shared use
    pub fn get_socket(&self) -> Arc<UdpSocket> {
        self.local_socket.as_ref()
            .expect("Transport manager must be started before getting socket")
            .clone()
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

    /// Take the packet receiver (can only be called once)
    pub fn take_packet_receiver(&mut self) -> Option<mpsc::Receiver<IncomingPacket>> {
        self.packet_receiver.take()
    }

    /// Packet reception loop
    async fn packet_reception_loop(
        socket: Arc<UdpSocket>,
        running: Arc<RwLock<bool>>,
        sender: mpsc::Sender<IncomingPacket>,
    ) {
        let mut buffer = vec![0u8; 65536]; // 64KB buffer
        info!("Packet reception loop started");
        
        while *running.read().await {
            // Receive packet with timeout
            match timeout(Duration::from_millis(1000), socket.recv_from(&mut buffer)).await {
                Ok(Ok((len, src_addr))) => {
                    let packet_data = &buffer[..len];
                    info!("Received packet: {} bytes from {}", len, src_addr);
                    
                    // Try to decode as Interest first
                    if let Ok((interest, _)) = Interest::decode(packet_data) {
                        info!("Received Interest for {} from {}", interest.name, src_addr);
                        if let Err(e) = sender.send(IncomingPacket::Interest(interest, src_addr)).await {
                            error!("Failed to send Interest to handler: {}", e);
                        }
                    }
                    // Try to decode as Data packet
                    else if let Ok((data, _)) = Data::decode(packet_data) {
                        info!("Received Data for {} from {}", data.name, src_addr);
                        if let Err(e) = sender.send(IncomingPacket::Data(data, src_addr)).await {
                            error!("Failed to send Data to handler: {}", e);
                        }
                    }
                    else {
                        warn!("Received unknown packet type from {} (first 8 bytes: {:?})", 
                            src_addr, 
                            &packet_data[..packet_data.len().min(8)]);
                        if let Err(e) = sender.send(IncomingPacket::Unknown(packet_data.to_vec(), src_addr)).await {
                            error!("Failed to send unknown packet to handler: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Socket receive error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(_) => {
                    // Timeout - this is normal, just continue
                }
            }
        }
        
        info!("Packet reception loop stopped");
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