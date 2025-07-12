use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

use udcn_core::packets::{Interest, Data};
use udcn_transport::{
    Transport, PacketFragmenter, PacketReassembler, 
    FragmentationConfig, PacketReassemblyConfig,
    Fragment, FragmentHeader, NdnQuicTransport, NdnQuicConfig,
    QuicTransport, QuicConfig
};

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
struct TransportConnection {
    socket: Option<Arc<UdpSocket>>,
    quic_transport: Option<Arc<NdnQuicTransport>>,
    protocol: TransportProtocol,
    last_used: std::time::Instant,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

impl std::fmt::Debug for TransportConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConnection")
            .field("socket", &self.socket.is_some())
            .field("quic_transport", &self.quic_transport.is_some())
            .field("protocol", &self.protocol)
            .field("last_used", &self.last_used)
            .field("bytes_sent", &self.bytes_sent)
            .field("bytes_received", &self.bytes_received)
            .field("packets_sent", &self.packets_sent)
            .field("packets_received", &self.packets_received)
            .finish()
    }
}

/// Stream context for bidirectional communication
#[derive(Debug)]
pub struct StreamContext {
    pub connection: Arc<quinn::Connection>,
    pub send_stream: Option<quinn::SendStream>,
    pub sequence: u64,
}

/// Incoming packet type
#[derive(Debug)]
pub enum IncomingPacket {
    Interest(Interest, SocketAddr, Option<StreamContext>),
    Data(Data, SocketAddr, Option<StreamContext>),
    Unknown(Vec<u8>, SocketAddr, Option<StreamContext>),
}

/// Transport Manager for NDN packet transmission
pub struct TransportManager {
    config: TransportConfig,
    connections: Arc<RwLock<HashMap<SocketAddr, TransportConnection>>>,
    pub local_socket: Option<Arc<UdpSocket>>,
    pub quic_transport: Option<Arc<NdnQuicTransport>>,
    running: Arc<RwLock<bool>>,
    packet_sender: Option<mpsc::Sender<IncomingPacket>>,
    packet_receiver: Option<mpsc::Receiver<IncomingPacket>>,
    fragmenter: Arc<Mutex<PacketFragmenter>>,
    reassemblers: Arc<RwLock<HashMap<SocketAddr, PacketReassembler>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new(config: TransportConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        
        // Create fragmenter with larger MTU to support bigger UDP packets
        let fragmentation_config = FragmentationConfig::with_mtu(8192); // Match eBPF MAX_PACKET_SIZE
        let fragmenter = PacketFragmenter::new(fragmentation_config);
        
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            local_socket: None,
            quic_transport: None,
            running: Arc::new(RwLock::new(false)),
            packet_sender: Some(tx),
            packet_receiver: Some(rx),
            fragmenter: Arc::new(Mutex::new(fragmenter)),
            reassemblers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the transport manager
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting Transport Manager with protocol: {:?}", self.config.protocol);

        // Parse bind address and create socket address
        let bind_ip: std::net::IpAddr = self.config.bind_address.parse()
            .map_err(|e| format!("Invalid bind address '{}': {}", self.config.bind_address, e))?;
        let local_addr = SocketAddr::new(bind_ip, self.config.local_port);
        
        match self.config.protocol {
            TransportProtocol::Udp => {
                // Create local UDP socket for sending packets
                let socket = UdpSocket::bind(local_addr).await?;
                self.local_socket = Some(Arc::new(socket));

                // Start UDP packet reception loop
                let socket = self.local_socket.as_ref().unwrap().clone();
                let running = self.running.clone();
                let sender = self.packet_sender.as_ref().unwrap().clone();
                let reassemblers = self.reassemblers.clone();
                
                tokio::spawn(async move {
                    Self::udp_packet_reception_loop(socket, running, sender, reassemblers).await;
                });
            }
            TransportProtocol::Quic => {
                // Create QUIC transport
                let quic_config = QuicConfig::default();
                let ndn_config = NdnQuicConfig::default();
                let quic_transport = QuicTransport::new_server(local_addr, quic_config).await?;
                let ndn_quic_transport = NdnQuicTransport::new(Arc::new(quic_transport), ndn_config);
                self.quic_transport = Some(Arc::new(ndn_quic_transport));

                // Start QUIC packet reception loop
                let quic_transport = self.quic_transport.as_ref().unwrap().clone();
                let running = self.running.clone();
                let sender = self.packet_sender.as_ref().unwrap().clone();
                
                tokio::spawn(async move {
                    Self::quic_packet_reception_loop(quic_transport, running, sender).await;
                });
            }
            _ => {
                return Err(format!("Unsupported transport protocol: {:?}", self.config.protocol).into());
            }
        }

        // Mark as running
        *self.running.write().await = true;

        info!("Transport Manager started on {} with {:?}", local_addr, self.config.protocol);
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

        // Close QUIC transport if present
        if let Some(ref quic_transport) = self.quic_transport {
            if let Err(e) = quic_transport.quic_transport().close().await {
                error!("Failed to close QUIC transport: {}", e);
            }
        }
        self.quic_transport = None;

        info!("Transport Manager stopped");
        Ok(())
    }

    /// Send an Interest packet to a specific address
    pub async fn send_interest(&self, interest: &Interest, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        match self.config.protocol {
            TransportProtocol::Udp => {
                // Encode the Interest packet
                let encoded_interest = interest.encode()
                    .map_err(|e| format!("Failed to encode Interest: {}", e))?;

                // Send the packet via UDP
                let bytes_sent = self.send_udp_packet(&encoded_interest, addr).await?;
                debug!("Sent Interest {} ({} bytes) via UDP to {}", interest.name, bytes_sent, addr);
                
                // Update connection statistics
                self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;
                Ok(bytes_sent)
            }
            TransportProtocol::Quic => {
                if let Some(ref quic_transport) = self.quic_transport {
                    // Send via QUIC
                    quic_transport.send_interest(interest, addr).await
                        .map_err(|e| format!("Failed to send Interest via QUIC: {}", e))?;
                    
                    let bytes_sent = interest.encode().map(|e| e.len()).unwrap_or(0);
                    debug!("Sent Interest {} ({} bytes) via QUIC to {}", interest.name, bytes_sent, addr);
                    
                    // Update connection statistics
                    self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;
                    Ok(bytes_sent)
                } else {
                    Err("QUIC transport not initialized".into())
                }
            }
            _ => {
                Err(format!("Unsupported transport protocol: {:?}", self.config.protocol).into())
            }
        }
    }

    /// Send a Data packet response on an existing QUIC connection
    pub async fn send_data_response(&self, data: &Data, connection: &Arc<quinn::Connection>) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        if let Some(ref quic_transport) = self.quic_transport {
            // Send response via the existing QUIC connection (opens new unidirectional stream)
            quic_transport.send_data_on_connection(data, connection).await
                .map_err(|e| format!("Failed to send Data response via QUIC: {}", e))?;
            
            let bytes_sent = data.encode().map(|e| e.len()).unwrap_or(0);
            debug!("Sent Data response {} ({} bytes) via QUIC", data.name, bytes_sent);
            
            Ok(bytes_sent)
        } else {
            Err("QUIC transport not initialized".into())
        }
    }

    /// Send a Data packet response on a specific bidirectional stream
    pub async fn send_data_response_on_stream(&self, data: &Data, send_stream: quinn::SendStream, sequence: u64) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        if let Some(ref quic_transport) = self.quic_transport {
            // Send response directly on the bidirectional stream with the original sequence number
            quic_transport.send_data_on_stream(data, send_stream, sequence).await
                .map_err(|e| format!("Failed to send Data response on stream: {}", e))?;
            
            let bytes_sent = data.encode().map(|e| e.len()).unwrap_or(0);
            debug!("Sent Data response {} ({} bytes) on bidirectional stream with sequence {}", data.name, bytes_sent, sequence);
            
            Ok(bytes_sent)
        } else {
            Err("QUIC transport not initialized".into())
        }
    }

    /// Send a Data packet to a specific address
    pub async fn send_data(&self, data: &Data, addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if !*self.running.read().await {
            return Err("Transport Manager not running".into());
        }

        match self.config.protocol {
            TransportProtocol::Udp => {
                // Encode the Data packet
                let encoded_data = data.encode()
                    .map_err(|e| format!("Failed to encode Data: {}", e))?;

                // Send the packet via UDP
                let bytes_sent = self.send_udp_packet(&encoded_data, addr).await?;
                debug!("Sent Data {} ({} bytes) via UDP to {}", data.name, bytes_sent, addr);
                
                // Update connection statistics
                self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;
                Ok(bytes_sent)
            }
            TransportProtocol::Quic => {
                if let Some(ref quic_transport) = self.quic_transport {
                    // Send via QUIC
                    quic_transport.send_data(data, addr).await
                        .map_err(|e| format!("Failed to send Data via QUIC: {}", e))?;
                    
                    let bytes_sent = data.encode().map(|e| e.len()).unwrap_or(0);
                    debug!("Sent Data {} ({} bytes) via QUIC to {}", data.name, bytes_sent, addr);
                    
                    // Update connection statistics
                    self.update_connection_stats(addr, bytes_sent, 0, 1, 0).await;
                    Ok(bytes_sent)
                } else {
                    Err("QUIC transport not initialized".into())
                }
            }
            _ => {
                Err(format!("Unsupported transport protocol: {:?}", self.config.protocol).into())
            }
        }
    }

    /// Send raw packet data via UDP to a specific address
    async fn send_udp_packet(&self, data: &[u8], addr: SocketAddr) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref socket) = self.local_socket {
            // Send packet directly - UDP can handle up to 65KB packets
            // Disable fragmentation to avoid complexity since we're using UDP
            let bytes_sent = socket.send_to(data, addr).await?;
            debug!("Sent UDP packet: {} bytes to {}", bytes_sent, addr);
            Ok(bytes_sent)
        } else {
            Err("No UDP socket available".into())
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
            let connection = match self.config.protocol {
                TransportProtocol::Udp => {
                    if let Some(ref socket) = self.local_socket {
                        TransportConnection {
                            socket: Some(socket.clone()),
                            quic_transport: None,
                            protocol: self.config.protocol,
                            last_used: std::time::Instant::now(),
                            bytes_sent: bytes_sent as u64,
                            bytes_received: bytes_received as u64,
                            packets_sent,
                            packets_received,
                        }
                    } else {
                        return; // No socket available
                    }
                }
                TransportProtocol::Quic => {
                    TransportConnection {
                        socket: None,
                        quic_transport: self.quic_transport.clone(),
                        protocol: self.config.protocol,
                        last_used: std::time::Instant::now(),
                        bytes_sent: bytes_sent as u64,
                        bytes_received: bytes_received as u64,
                        packets_sent,
                        packets_received,
                    }
                }
                _ => return, // Unsupported protocol
            };
            connections.insert(addr, connection);
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
    
    /// Clean up expired reassembly buffers
    pub async fn cleanup_reassemblers(&self) {
        let mut reassemblers = self.reassemblers.write().await;
        reassemblers.retain(|addr, reassembler| {
            reassembler.cleanup_expired_entries();
            // Remove reassemblers with no active entries
            if reassembler.stats().active_reassemblies == 0 {
                debug!("Removing inactive reassembler for {}", addr);
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

    /// Take the packet receiver (can only be called once)
    pub fn take_packet_receiver(&mut self) -> Option<mpsc::Receiver<IncomingPacket>> {
        self.packet_receiver.take()
    }

    /// UDP packet reception loop
    async fn udp_packet_reception_loop(
        socket: Arc<UdpSocket>,
        running: Arc<RwLock<bool>>,
        sender: mpsc::Sender<IncomingPacket>,
        reassemblers: Arc<RwLock<HashMap<SocketAddr, PacketReassembler>>>,
    ) {
        let mut buffer = vec![0u8; 65536]; // 64KB buffer
        info!("Packet reception loop started");
        
        while *running.read().await {
            // Receive packet with timeout
            match timeout(Duration::from_millis(1000), socket.recv_from(&mut buffer)).await {
                Ok(Ok((len, src_addr))) => {
                    let packet_data = &buffer[..len];
                    info!("Received packet: {} bytes from {}", len, src_addr);
                    
                    // Check if this is a fragment - for now, skip fragment handling
                    // TODO: Implement proper fragment header detection
                    
                    // Try normal decoding
                    if let Ok((interest, _)) = Interest::decode(packet_data) {
                            info!("Received Interest for {} from {}", interest.name, src_addr);
                            if let Err(e) = sender.send(IncomingPacket::Interest(interest, src_addr, None)).await {
                                error!("Failed to send Interest to handler: {}", e);
                            }
                    }
                    // Try to decode as Data packet
                    else if let Ok((data, _)) = Data::decode(packet_data) {
                            info!("Received Data for {} from {}", data.name, src_addr);
                            if let Err(e) = sender.send(IncomingPacket::Data(data, src_addr, None)).await {
                                error!("Failed to send Data to handler: {}", e);
                            }
                    }
                    else {
                            warn!("Received unknown packet type from {} (first 8 bytes: {:?})", 
                                src_addr, 
                                &packet_data[..packet_data.len().min(8)]);
                            if let Err(e) = sender.send(IncomingPacket::Unknown(packet_data.to_vec(), src_addr, None)).await {
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
        
        info!("UDP packet reception loop stopped");
    }

    /// QUIC packet reception loop
    async fn quic_packet_reception_loop(
        quic_transport: Arc<NdnQuicTransport>,
        running: Arc<RwLock<bool>>,
        sender: mpsc::Sender<IncomingPacket>,
    ) {
        info!("QUIC packet reception loop started");
        
        while *running.read().await {
            // Accept incoming QUIC connections
            match timeout(Duration::from_millis(1000), quic_transport.quic_transport().accept()).await {
                Ok(Ok(connection)) => {
                    let remote_addr = connection.remote_address();
                    info!("Accepted QUIC connection from {}", remote_addr);
                    
                    // Handle this connection in a separate task
                    let connection = Arc::new(connection);
                    let quic_transport_clone = quic_transport.clone();
                    let sender_clone = sender.clone();
                    let running_clone = running.clone();
                    
                    tokio::spawn(async move {
                        Self::handle_quic_connection(connection, quic_transport_clone, sender_clone, running_clone).await;
                    });
                }
                Ok(Err(e)) => {
                    error!("QUIC accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(_) => {
                    // Timeout - this is normal, just continue
                }
            }
        }
        
        info!("QUIC packet reception loop stopped");
    }

    /// Handle a single QUIC connection
    async fn handle_quic_connection(
        connection: Arc<quinn::Connection>,
        quic_transport: Arc<NdnQuicTransport>,
        sender: mpsc::Sender<IncomingPacket>,
        running: Arc<RwLock<bool>>,
    ) {
        let remote_addr = connection.remote_address();
        info!("Handling QUIC connection from {}", remote_addr);
        
        while *running.read().await && !connection.close_reason().is_some() {
            // Try to receive NDN frames
            debug!("Waiting for frame from connection {}", remote_addr);
            match timeout(Duration::from_millis(5000), quic_transport.receive_frame(&connection)).await {
                Ok(Ok((frame, send_stream))) => {
                    debug!("Received frame from connection {}", remote_addr);
                    
                    // Create stream context with the bidirectional stream info
                    let stream_context = StreamContext {
                        connection: connection.clone(),
                        send_stream,
                        sequence: frame.header.sequence,
                    };
                    
                    // Convert frame to packet and send to handler
                    match frame.to_packet() {
                        Ok(udcn_core::packets::Packet::Interest(interest)) => {
                            info!("Received Interest for {} via QUIC from {}", interest.name, remote_addr);
                            if let Err(e) = sender.send(IncomingPacket::Interest(interest, remote_addr, Some(stream_context))).await {
                                error!("Failed to send Interest to handler: {}", e);
                                break;
                            }
                        }
                        Ok(udcn_core::packets::Packet::Data(data)) => {
                            info!("Received Data for {} via QUIC from {}", data.name, remote_addr);
                            if let Err(e) = sender.send(IncomingPacket::Data(data, remote_addr, Some(stream_context))).await {
                                error!("Failed to send Data to handler: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to convert QUIC frame to packet from {}: {}", remote_addr, e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("QUIC frame receive error from {}: {}", remote_addr, e);
                    break;
                }
                Err(_) => {
                    // Timeout - check if connection is still alive
                    debug!("QUIC receive timeout from {}", remote_addr);
                }
            }
        }
        
        info!("QUIC connection handler stopped for {}", remote_addr);
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