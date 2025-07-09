use std::sync::{Arc, Mutex};
use crate::{
    Transport, 
    PacketFragmenter, 
    PacketReassembler, 
    FragmentationConfig, 
    PacketReassemblyConfig,
    Fragment,
    FragmentationError,
    ReassemblyError,
    PacketReassemblyStats,
};

/// Enhanced transport layer with packet fragmentation and reassembly support
#[derive(Debug)]
pub struct FragmentedTransport<T: Transport> {
    /// Underlying transport implementation
    inner_transport: T,
    /// Packet fragmenter for outgoing packets
    fragmenter: Arc<Mutex<PacketFragmenter>>,
    /// Packet reassembler for incoming fragments
    reassembler: Arc<Mutex<PacketReassembler>>,
    /// Fragmentation configuration
    fragmentation_config: FragmentationConfig,
    /// Reassembly configuration
    reassembly_config: PacketReassemblyConfig,
}

impl<T: Transport> FragmentedTransport<T> {
    /// Create a new fragmented transport wrapper
    pub fn new(
        transport: T, 
        fragmentation_config: FragmentationConfig, 
        reassembly_config: PacketReassemblyConfig
    ) -> Self {
        let fragmenter = PacketFragmenter::new(fragmentation_config.clone());
        let reassembler = PacketReassembler::new(reassembly_config.clone());
        
        Self {
            inner_transport: transport,
            fragmenter: Arc::new(Mutex::new(fragmenter)),
            reassembler: Arc::new(Mutex::new(reassembler)),
            fragmentation_config,
            reassembly_config,
        }
    }

    /// Create with default configurations
    pub fn with_defaults(transport: T) -> Self {
        Self::new(
            transport,
            FragmentationConfig::default(),
            PacketReassemblyConfig::default(),
        )
    }

    /// Create with custom MTU
    pub fn with_mtu(transport: T, mtu: usize) -> Self {
        Self::new(
            transport,
            FragmentationConfig::with_mtu(mtu),
            PacketReassemblyConfig::default(),
        )
    }

    /// Get fragmentation statistics
    pub fn fragmentation_config(&self) -> &FragmentationConfig {
        &self.fragmentation_config
    }

    /// Get reassembly statistics
    pub fn reassembly_stats(&self) -> Result<PacketReassemblyStats, Box<dyn std::error::Error>> {
        let reassembler = self.reassembler.lock()
            .map_err(|_| FragmentedTransportError::LockError)?;
        Ok(reassembler.stats().clone())
    }

    /// Force cleanup of expired reassembly entries
    pub fn cleanup_reassembly(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut reassembler = self.reassembler.lock()
            .map_err(|_| FragmentedTransportError::LockError)?;
        reassembler.cleanup_expired_entries();
        Ok(())
    }

    /// Get the underlying transport
    pub fn inner(&self) -> &T {
        &self.inner_transport
    }

    /// Consume the fragmented transport and return the inner transport
    pub fn into_inner(self) -> T {
        self.inner_transport
    }
}

impl<T: Transport> Transport for FragmentedTransport<T> {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Fragment the packet if necessary
        let mut fragmenter = self.fragmenter.lock()
            .map_err(|_| FragmentedTransportError::LockError)?;
        
        let fragments = fragmenter.fragment_packet(data)?;
        
        // Send each fragment over the underlying transport
        for fragment in fragments {
            let fragment_bytes = fragment.to_bytes();
            self.inner_transport.send(&fragment_bytes)?;
        }
        
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        loop {
            // Receive data from underlying transport
            let fragment_bytes = self.inner_transport.receive()?;
            
            // Parse fragment from received bytes
            let fragment = parse_fragment_from_bytes(&fragment_bytes)?;
            
            // Process fragment through reassembler
            let mut reassembler = self.reassembler.lock()
                .map_err(|_| FragmentedTransportError::LockError)?;
            
            match reassembler.process_fragment(fragment)? {
                Some(reassembled_packet) => {
                    // Complete packet reassembled
                    return Ok(reassembled_packet);
                }
                None => {
                    // Still waiting for more fragments, continue receiving
                    continue;
                }
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner_transport.close()
    }
}

/// Parse a fragment from received bytes
fn parse_fragment_from_bytes(data: &[u8]) -> Result<Fragment, FragmentedTransportError> {
    if data.len() < 32 { // Minimum header size
        return Err(FragmentedTransportError::InvalidFragmentData);
    }

    // Find the boundary between header and payload
    // This is a simplified parser - in practice you'd need proper TLV parsing
    let header_size = find_header_boundary(data)?;
    
    let header_bytes = &data[..header_size];
    let payload = data[header_size..].to_vec();
    
    let header = crate::FragmentHeader::from_bytes(header_bytes)
        .map_err(|_| FragmentedTransportError::InvalidFragmentData)?;
    
    Ok(Fragment::new(header, payload))
}

/// Find the boundary between header and payload in fragment data
fn find_header_boundary(data: &[u8]) -> Result<usize, FragmentedTransportError> {
    // For simplicity, assume the header is serialized with a length prefix
    // In practice, you'd implement proper TLV parsing based on the fragment header format
    
    // Try to deserialize potential header sizes
    for potential_size in (16..=128).step_by(8) {
        if potential_size > data.len() {
            break;
        }
        
        if let Ok(_) = crate::FragmentHeader::from_bytes(&data[..potential_size]) {
            return Ok(potential_size);
        }
    }
    
    Err(FragmentedTransportError::InvalidFragmentData)
}

/// Errors specific to fragmented transport operations
#[derive(Debug, thiserror::Error)]
pub enum FragmentedTransportError {
    #[error("Failed to acquire lock on fragmenter/reassembler")]
    LockError,
    
    #[error("Invalid fragment data received")]
    InvalidFragmentData,
    
    #[error("Fragmentation error: {0}")]
    FragmentationError(#[from] FragmentationError),
    
    #[error("Reassembly error: {0}")]
    ReassemblyError(#[from] ReassemblyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TcpTransport, UdpTransport};
    use std::net::SocketAddr;

    // Mock transport for testing
    #[derive(Debug)]
    struct MockTransport {
        send_buffer: Arc<Mutex<Vec<Vec<u8>>>>,
        receive_buffer: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                send_buffer: Arc::new(Mutex::new(Vec::new())),
                receive_buffer: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn add_to_receive_buffer(&self, data: Vec<u8>) {
            self.receive_buffer.lock().unwrap().push(data);
        }

        fn get_sent_data(&self) -> Vec<Vec<u8>> {
            self.send_buffer.lock().unwrap().clone()
        }
    }

    impl Transport for MockTransport {
        fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            self.send_buffer.lock().unwrap().push(data.to_vec());
            Ok(())
        }

        fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut buffer = self.receive_buffer.lock().unwrap();
            if buffer.is_empty() {
                return Err("No data available".into());
            }
            Ok(buffer.remove(0))
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn test_small_packet_no_fragmentation() {
        let mock_transport = MockTransport::new();
        let fragmented_transport = FragmentedTransport::with_defaults(mock_transport);
        
        let small_packet = vec![1, 2, 3, 4, 5];
        
        // Send should not fragment small packets
        fragmented_transport.send(&small_packet).unwrap();
        
        let sent_data = fragmented_transport.inner().get_sent_data();
        assert_eq!(sent_data.len(), 1); // Single fragment sent
    }

    #[test]
    fn test_large_packet_fragmentation() {
        let mock_transport = MockTransport::new();
        let config = FragmentationConfig::with_mtu(600);
        let fragmented_transport = FragmentedTransport::new(
            mock_transport, 
            config, 
            PacketReassemblyConfig::default()
        );
        
        let large_packet = vec![42u8; 2000]; // Large packet requiring fragmentation
        
        fragmented_transport.send(&large_packet).unwrap();
        
        let sent_data = fragmented_transport.inner().get_sent_data();
        assert!(sent_data.len() > 1); // Multiple fragments sent
    }

    #[test]
    fn test_fragmentation_config() {
        let mock_transport = MockTransport::new();
        let fragmented_transport = FragmentedTransport::with_mtu(mock_transport, 1200);
        
        assert_eq!(fragmented_transport.fragmentation_config().mtu, 1200);
        assert!(fragmented_transport.fragmentation_config().max_fragment_size < 1200);
    }

    #[test]
    fn test_reassembly_stats() {
        let mock_transport = MockTransport::new();
        let fragmented_transport = FragmentedTransport::with_defaults(mock_transport);
        
        let stats = fragmented_transport.reassembly_stats().unwrap();
        assert_eq!(stats.fragments_received, 0);
        assert_eq!(stats.packets_reassembled, 0);
    }
}