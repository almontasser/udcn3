use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use anyhow::{Result, Context};
use log::{info, error, debug};
use tokio::sync::RwLock;
use quinn::{
    Connection, Endpoint, ServerConfig, ClientConfig, 
    TransportConfig
};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig, ClientConfig as RustlsClientConfig};
use rustls::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};
use rustls::kx_group::{X25519, SECP256R1, SECP384R1};
use rustls::version::TLS13;
use rcgen::{Certificate as RcgenCertificate, CertificateParams};

use crate::Transport;

/// QUIC transport configuration
#[derive(Clone)]
pub struct QuicConfig {
    pub max_idle_timeout: Duration,
    pub max_concurrent_streams: u32,
    pub max_stream_bandwidth: u32,
    pub keep_alive_interval: Duration,
    pub tls_config: TlsSecurityConfig,
}

/// TLS security configuration
#[derive(Clone)]
pub struct TlsSecurityConfig {
    pub cipher_suites: Vec<rustls::SupportedCipherSuite>,
    pub key_exchange_groups: Vec<&'static rustls::SupportedKxGroup>,
    pub protocol_versions: Vec<&'static rustls::SupportedProtocolVersion>,
    pub require_client_auth: bool,
    pub verify_hostname: bool,
    pub certificate_transparency: bool,
    pub ocsp_stapling: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            max_concurrent_streams: 100,
            max_stream_bandwidth: 1024 * 1024, // 1MB/s
            keep_alive_interval: Duration::from_secs(10),
            tls_config: TlsSecurityConfig::default(),
        }
    }
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            cipher_suites: vec![
                TLS13_AES_256_GCM_SHA384,
                TLS13_AES_128_GCM_SHA256,
                TLS13_CHACHA20_POLY1305_SHA256,
            ],
            key_exchange_groups: vec![
                &X25519,
                &SECP384R1,
                &SECP256R1,
            ],
            protocol_versions: vec![&TLS13],
            require_client_auth: false,
            verify_hostname: true,
            certificate_transparency: false,
            ocsp_stapling: false,
        }
    }
}

impl TlsSecurityConfig {
    /// Create a high-security configuration
    pub fn high_security() -> Self {
        Self {
            cipher_suites: vec![
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
            ],
            key_exchange_groups: vec![
                &X25519,
                &SECP384R1,
            ],
            protocol_versions: vec![&TLS13],
            require_client_auth: true,
            verify_hostname: true,
            certificate_transparency: true,
            ocsp_stapling: true,
        }
    }
    
    /// Create a development/testing configuration with relaxed security
    pub fn development() -> Self {
        Self {
            cipher_suites: vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
            ],
            key_exchange_groups: vec![
                &X25519,
                &SECP256R1,
                &SECP384R1,
            ],
            protocol_versions: vec![&TLS13],
            require_client_auth: false,
            verify_hostname: false,
            certificate_transparency: false,
            ocsp_stapling: false,
        }
    }
}

/// Connection pool entry
#[derive(Clone)]
struct ConnectionEntry {
    connection: Connection,
    created_at: std::time::Instant,
    last_used: std::time::Instant,
}

/// QUIC transport implementation
pub struct QuicTransport {
    endpoint: Endpoint,
    config: QuicConfig,
    connections: Arc<RwLock<HashMap<SocketAddr, ConnectionEntry>>>,
    server_mode: bool,
}

impl QuicTransport {
    /// Create a new QUIC transport in server mode
    pub async fn new_server(bind_addr: SocketAddr, config: QuicConfig) -> Result<Self> {
        let (cert_der, key_der) = generate_self_signed_cert()?;
        
        let rustls_config = create_rustls_server_config(&config.tls_config, cert_der, key_der)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(rustls_config));
        let transport_config = create_transport_config(&config);
        server_config.transport_config(Arc::new(transport_config));
        
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("Failed to create server endpoint")?;
        
        info!("QUIC server listening on {} with TLS security", bind_addr);
        
        Ok(Self {
            endpoint,
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            server_mode: true,
        })
    }
    
    /// Create a new QUIC transport in client mode
    pub async fn new_client(config: QuicConfig) -> Result<Self> {
        let rustls_config = create_rustls_client_config(&config.tls_config)?;
        let mut client_config = ClientConfig::new(Arc::new(rustls_config));
        let transport_config = create_transport_config(&config);
        client_config.transport_config(Arc::new(transport_config));
        
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)
            .context("Failed to create client endpoint")?;
        endpoint.set_default_client_config(client_config);
        
        info!("QUIC client initialized with TLS security");
        
        Ok(Self {
            endpoint,
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            server_mode: false,
        })
    }
    
    /// Establish a connection to a remote peer
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<Connection> {
        if self.server_mode {
            return Err(anyhow::anyhow!("Cannot connect in server mode"));
        }
        
        // Check if we already have a connection
        {
            let connections = self.connections.read().await;
            if let Some(entry) = connections.get(&remote_addr) {
                if !entry.connection.close_reason().is_some() {
                    debug!("Reusing existing connection to {}", remote_addr);
                    return Ok(entry.connection.clone());
                }
            }
        }
        
        debug!("Establishing new connection to {}", remote_addr);
        let connection = self.endpoint
            .connect(remote_addr, "localhost")?
            .await?;
        
        // Store the connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(remote_addr, ConnectionEntry {
                connection: connection.clone(),
                created_at: std::time::Instant::now(),
                last_used: std::time::Instant::now(),
            });
        }
        
        info!("Connected to {}", remote_addr);
        Ok(connection)
    }
    
    /// Accept incoming connections (server mode)
    pub async fn accept(&self) -> Result<Connection> {
        if !self.server_mode {
            return Err(anyhow::anyhow!("Cannot accept in client mode"));
        }
        
        let connection = self.endpoint.accept().await
            .context("Failed to accept connection")?
            .await?;
        
        let remote_addr = connection.remote_address();
        
        // Store the connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(remote_addr, ConnectionEntry {
                connection: connection.clone(),
                created_at: std::time::Instant::now(),
                last_used: std::time::Instant::now(),
            });
        }
        
        info!("Accepted connection from {}", remote_addr);
        Ok(connection)
    }
    
    /// Send data through a connection
    pub async fn send_to(&self, remote_addr: SocketAddr, data: &[u8]) -> Result<()> {
        let connection = if self.server_mode {
            // In server mode, find existing connection
            let connections = self.connections.read().await;
            connections.get(&remote_addr)
                .ok_or_else(|| anyhow::anyhow!("No connection to {}", remote_addr))?
                .connection.clone()
        } else {
            // In client mode, establish connection if needed
            self.connect(remote_addr).await?
        };
        
        let mut send_stream = connection.open_uni().await?;
        send_stream.write_all(data).await?;
        send_stream.finish().await?;
        
        // Update last used time
        {
            let mut connections = self.connections.write().await;
            if let Some(entry) = connections.get_mut(&remote_addr) {
                entry.last_used = std::time::Instant::now();
            }
        }
        
        debug!("Sent {} bytes to {}", data.len(), remote_addr);
        Ok(())
    }

    /// Send data on an existing connection
    pub async fn send_to_connection(&self, connection: &Arc<Connection>, data: &[u8]) -> Result<()> {
        let mut send_stream = connection.open_uni().await?;
        send_stream.write_all(data).await?;
        send_stream.finish().await?;
        
        debug!("Sent {} bytes on existing connection", data.len());
        Ok(())
    }
    
    /// Send data on a specific connection using a provided send stream (for bidirectional responses)
    pub async fn send_data_on_connection(&self, _connection: &Arc<Connection>, send_stream: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
        send_stream.write_all(data).await?;
        // Don't finish the stream immediately - let the caller decide when to close it
        
        debug!("Sent {} bytes on bidirectional stream", data.len());
        Ok(())
    }
    
    /// Receive data from a connection (accepts both unidirectional and bidirectional streams)
    /// Returns the received data and optionally a send stream for bidirectional responses
    pub async fn receive_from(&self, connection: &Connection) -> Result<(Vec<u8>, Option<quinn::SendStream>)> {
        debug!("Attempting to receive data from connection {}", connection.remote_address());
        
        // First try to accept a bidirectional stream (which is what the CLI uses)
        match tokio::time::timeout(std::time::Duration::from_millis(5000), connection.accept_bi()).await {
            Ok(Ok((send_stream, mut recv_stream))) => {
                debug!("Accepted bidirectional stream from {}", connection.remote_address());
                
                // For bidirectional streams, read with timeout instead of read_to_end
                // since the client may not close the send side immediately
                let mut buffer = Vec::new();
                let mut temp_buffer = [0u8; 8192];
                
                loop {
                    match tokio::time::timeout(std::time::Duration::from_millis(1000), recv_stream.read(&mut temp_buffer)).await {
                        Ok(Ok(Some(0))) => break, // Stream closed
                        Ok(Ok(Some(n))) => {
                            buffer.extend_from_slice(&temp_buffer[..n]);
                            // Check if we've received what looks like a complete frame
                            if buffer.len() >= 4 {
                                // Read the length from the frame header
                                let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                                if buffer.len() >= length + 4 {
                                    // We have a complete frame
                                    break;
                                }
                            }
                        }
                        Ok(Ok(None)) => {
                            // No more data available, but stream not closed
                            if !buffer.is_empty() {
                                break;
                            }
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_timeout) => {
                            // Timeout - if we have any data, use it
                            if !buffer.is_empty() {
                                break;
                            }
                            return Err(anyhow::anyhow!("Timeout reading from bidirectional stream"));
                        }
                    }
                }
                
                debug!("Received {} bytes from bidirectional stream on {}", buffer.len(), connection.remote_address());
                
                // Return both the data and the send stream for responses
                Ok((buffer, Some(send_stream)))
            }
            Ok(Err(e)) => {
                debug!("Failed to accept bidirectional stream: {}, trying unidirectional", e);
                // Fall back to unidirectional stream
                let mut recv_stream = connection.accept_uni().await?;
                let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                debug!("Received {} bytes from unidirectional stream on {}", buffer.len(), connection.remote_address());
                Ok((buffer, None))
            }
            Err(_timeout) => {
                debug!("Timeout accepting bidirectional stream, trying unidirectional");
                // Fall back to unidirectional stream
                let mut recv_stream = connection.accept_uni().await?;
                let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                debug!("Received {} bytes from unidirectional stream on {}", buffer.len(), connection.remote_address());
                Ok((buffer, None))
            }
        }
    }
    
    /// Close a specific connection
    pub async fn close_connection(&self, remote_addr: SocketAddr) -> Result<()> {
        let mut connections = self.connections.write().await;
        if let Some(entry) = connections.remove(&remote_addr) {
            entry.connection.close(0u32.into(), b"Connection closed by user");
            info!("Closed connection to {}", remote_addr);
        }
        Ok(())
    }
    
    /// Clean up stale connections
    pub async fn cleanup_stale_connections(&self) -> Result<()> {
        let mut connections = self.connections.write().await;
        let now = std::time::Instant::now();
        let timeout = self.config.max_idle_timeout;
        
        let mut to_remove = Vec::new();
        for (addr, entry) in connections.iter() {
            if now.duration_since(entry.last_used) > timeout || 
               entry.connection.close_reason().is_some() {
                to_remove.push(*addr);
            }
        }
        
        for addr in to_remove {
            if let Some(entry) = connections.remove(&addr) {
                entry.connection.close(0u32.into(), b"Connection timeout");
                debug!("Cleaned up stale connection to {}", addr);
            }
        }
        
        Ok(())
    }
    
    /// Get connection statistics
    pub async fn get_connection_stats(&self) -> HashMap<SocketAddr, ConnectionStats> {
        let connections = self.connections.read().await;
        let mut stats = HashMap::new();
        
        for (addr, entry) in connections.iter() {
            let connection_stats = ConnectionStats {
                remote_address: *addr,
                created_at: entry.created_at,
                last_used: entry.last_used,
                is_closed: entry.connection.close_reason().is_some(),
                rtt: entry.connection.rtt(),
            };
            stats.insert(*addr, connection_stats);
        }
        
        stats
    }
    
    /// Get the local address of the endpoint
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
            .map_err(|e| anyhow::anyhow!("Failed to get local address: {}", e))
    }
    
    /// Close the transport and all connections
    pub async fn close(&self) -> Result<()> {
        // Close all connections
        let connections = self.connections.read().await;
        for (_, entry) in connections.iter() {
            entry.connection.close(0u32.into(), b"Transport shutting down");
        }
        
        // Close the endpoint
        self.endpoint.close(0u32.into(), b"Transport shutting down");
        
        info!("QUIC transport closed");
        Ok(())
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub remote_address: SocketAddr,
    pub created_at: std::time::Instant,
    pub last_used: std::time::Instant,
    pub is_closed: bool,
    pub rtt: Duration,
}

/// Certificate validation and management
pub struct CertificateManager {
    cert_store: HashMap<String, (Certificate, PrivateKey)>,
}

impl CertificateManager {
    pub fn new() -> Self {
        Self {
            cert_store: HashMap::new(),
        }
    }
    
    /// Generate a certificate for a specific subject
    pub fn generate_cert_for_subject(&mut self, subject: &str) -> Result<(Certificate, PrivateKey)> {
        if let Some(cert) = self.cert_store.get(subject) {
            debug!("Reusing existing certificate for subject: {}", subject);
            return Ok(cert.clone());
        }
        
        let mut params = CertificateParams::new(vec![subject.to_string()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        
        // Add additional security parameters
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        
        let cert = RcgenCertificate::from_params(params)?;
        let cert_der = Certificate(cert.serialize_der()?);
        let key_der = PrivateKey(cert.serialize_private_key_der());
        
        self.cert_store.insert(subject.to_string(), (cert_der.clone(), key_der.clone()));
        info!("Generated new certificate for subject: {}", subject);
        
        Ok((cert_der, key_der))
    }
    
    /// Generate a certificate with SAN (Subject Alternative Names)
    pub fn generate_cert_with_san(&mut self, subject: &str, san_list: Vec<String>) -> Result<(Certificate, PrivateKey)> {
        let cache_key = format!("{}:{}", subject, san_list.join(","));
        
        if let Some(cert) = self.cert_store.get(&cache_key) {
            debug!("Reusing existing certificate for subject: {} with SAN", subject);
            return Ok(cert.clone());
        }
        
        let san_count = san_list.len();
        let mut params = CertificateParams::new(san_list);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        
        // Add key usage extensions for enhanced security
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
            rcgen::KeyUsagePurpose::KeyAgreement,
        ];
        
        let cert = RcgenCertificate::from_params(params)?;
        let cert_der = Certificate(cert.serialize_der()?);
        let key_der = PrivateKey(cert.serialize_private_key_der());
        
        self.cert_store.insert(cache_key, (cert_der.clone(), key_der.clone()));
        info!("Generated new certificate for subject: {} with {} SAN entries", subject, san_count);
        
        Ok((cert_der, key_der))
    }
}

/// Generate self-signed certificate for testing
fn generate_self_signed_cert() -> Result<(Certificate, PrivateKey)> {
    let mut cert_manager = CertificateManager::new();
    cert_manager.generate_cert_for_subject("localhost")
}

/// Create rustls server configuration with enhanced security
fn create_rustls_server_config(
    tls_config: &TlsSecurityConfig,
    cert: Certificate,
    key: PrivateKey,
) -> Result<RustlsServerConfig> {
    let config = RustlsServerConfig::builder()
        .with_cipher_suites(&tls_config.cipher_suites)
        .with_kx_groups(&tls_config.key_exchange_groups)
        .with_protocol_versions(&tls_config.protocol_versions)
        .context("Failed to create server config builder")?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("Failed to set certificate and key")?;
    
    // Configure additional security settings
    if tls_config.require_client_auth {
        // This would require implementing client certificate validation
        info!("Client authentication required but not yet implemented");
    }
    
    info!("Server TLS configuration: cipher_suites={}, kx_groups={}, client_auth={}", 
          tls_config.cipher_suites.len(),
          tls_config.key_exchange_groups.len(),
          tls_config.require_client_auth);
    
    Ok(config)
}

/// Create rustls client configuration with enhanced security
fn create_rustls_client_config(tls_config: &TlsSecurityConfig) -> Result<RustlsClientConfig> {
    if tls_config.verify_hostname {
        // Load native root certificates
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs()
            .context("Failed to load native certificates")?;
        
        for cert in native_certs {
            root_store.add(&rustls::Certificate(cert.0))
                .context("Failed to add native certificate to root store")?;
        }
        
        let config = RustlsClientConfig::builder()
            .with_cipher_suites(&tls_config.cipher_suites)
            .with_kx_groups(&tls_config.key_exchange_groups)
            .with_protocol_versions(&tls_config.protocol_versions)
            .context("Failed to create client config builder")?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        info!("Client TLS configuration: cipher_suites={}, kx_groups={}, verify_hostname=true", 
              tls_config.cipher_suites.len(),
              tls_config.key_exchange_groups.len());
        
        Ok(config)
    } else {
        // For development/testing - disable certificate verification
        use rustls::client::{ServerCertVerifier, ServerCertVerified};
        use rustls::{Error as TlsError, ServerName};
        
        struct NoVerifier;
        
        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<ServerCertVerified, TlsError> {
                Ok(ServerCertVerified::assertion())
            }
        }
        
        let config = RustlsClientConfig::builder()
            .with_cipher_suites(&tls_config.cipher_suites)
            .with_kx_groups(&tls_config.key_exchange_groups)
            .with_protocol_versions(&tls_config.protocol_versions)
            .context("Failed to create client config builder")?
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        
        info!("Client TLS configuration: cipher_suites={}, kx_groups={}, verify_hostname=false", 
              tls_config.cipher_suites.len(),
              tls_config.key_exchange_groups.len());
        
        Ok(config)
    }
}

/// Create transport configuration
fn create_transport_config(config: &QuicConfig) -> TransportConfig {
    let mut transport_config = TransportConfig::default();
    
    transport_config.max_idle_timeout(Some(config.max_idle_timeout.try_into().unwrap()));
    transport_config.max_concurrent_uni_streams(config.max_concurrent_streams.into());
    transport_config.max_concurrent_bidi_streams(config.max_concurrent_streams.into());
    transport_config.keep_alive_interval(Some(config.keep_alive_interval));
    
    transport_config
}

/// Simple wrapper for compatibility with existing Transport trait
pub struct QuicTransportWrapper {
    transport: Arc<QuicTransport>,
    default_remote: Option<SocketAddr>,
}

impl QuicTransportWrapper {
    pub fn new(transport: QuicTransport, default_remote: Option<SocketAddr>) -> Self {
        Self {
            transport: Arc::new(transport),
            default_remote,
        }
    }
    
    pub fn transport(&self) -> &Arc<QuicTransport> {
        &self.transport
    }
}

impl Transport for QuicTransportWrapper {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let remote = self.default_remote
            .ok_or("No default remote address set")?;
        
        let transport = self.transport.clone();
        let data = data.to_vec();
        
        tokio::spawn(async move {
            if let Err(e) = transport.send_to(remote, &data).await {
                error!("Failed to send data: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // This is a simplified implementation
        // In practice, you'd want to handle this differently
        Err("Synchronous receive not supported for QUIC".into())
    }
    
    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        let transport = self.transport.clone();
        
        tokio::spawn(async move {
            if let Err(e) = transport.close().await {
                error!("Failed to close transport: {}", e);
            }
        });
        
        Ok(())
    }
}