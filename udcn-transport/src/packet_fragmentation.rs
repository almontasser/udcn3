use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Default MTU size for Ethernet networks
pub const DEFAULT_MTU: usize = 1500;

/// Minimum fragment size to avoid excessive overhead
pub const MIN_FRAGMENT_SIZE: usize = 64;

/// Maximum reassembly timeout in seconds
pub const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Fragment header structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragmentHeader {
    /// Unique identifier for the original packet
    pub packet_id: u32,
    /// Fragment sequence number (0-based)
    pub fragment_id: u16,
    /// Total number of fragments for this packet
    pub total_fragments: u16,
    /// Size of this fragment's payload
    pub fragment_size: u16,
    /// Checksum of the fragment payload
    pub checksum: u32,
    /// Flags for fragment options
    pub flags: u8,
}

/// Fragment flags
pub mod fragment_flags {
    /// More fragments follow
    pub const MORE_FRAGMENTS: u8 = 0x01;
    /// Don't fragment (for testing/diagnostics)
    pub const DONT_FRAGMENT: u8 = 0x02;
    /// High priority fragment
    pub const HIGH_PRIORITY: u8 = 0x04;
}

impl FragmentHeader {
    /// Create a new fragment header
    pub fn new(packet_id: u32, fragment_id: u16, total_fragments: u16, fragment_size: u16) -> Self {
        Self {
            packet_id,
            fragment_id,
            total_fragments,
            fragment_size,
            checksum: 0,
            flags: if fragment_id < total_fragments - 1 { 
                fragment_flags::MORE_FRAGMENTS 
            } else { 
                0 
            },
        }
    }

    /// Check if this is the last fragment
    pub fn is_last_fragment(&self) -> bool {
        self.fragment_id == self.total_fragments - 1
    }

    /// Check if more fragments follow
    pub fn has_more_fragments(&self) -> bool {
        (self.flags & fragment_flags::MORE_FRAGMENTS) != 0
    }

    /// Calculate checksum for the fragment payload
    pub fn calculate_checksum(data: &[u8]) -> u32 {
        // Simple checksum implementation (replace with crc32fast when available)
        data.iter().fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32))
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(data)?)
    }
}

/// Fragmented packet data
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment header
    pub header: FragmentHeader,
    /// Fragment payload
    pub payload: Vec<u8>,
    /// Timestamp when fragment was created/received
    pub timestamp: Instant,
}

impl Fragment {
    /// Create a new fragment
    pub fn new(header: FragmentHeader, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            timestamp: Instant::now(),
        }
    }

    /// Validate fragment integrity
    pub fn validate(&self) -> bool {
        self.header.fragment_size as usize == self.payload.len() &&
        self.header.checksum == FragmentHeader::calculate_checksum(&self.payload)
    }

    /// Serialize fragment to bytes (header + payload)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.header.to_bytes();
        result.extend_from_slice(&self.payload);
        result
    }
}

/// Configuration for packet fragmentation
#[derive(Debug, Clone)]
pub struct FragmentationConfig {
    /// Maximum transmission unit size
    pub mtu: usize,
    /// Fragment header overhead size
    pub header_overhead: usize,
    /// Maximum fragment payload size
    pub max_fragment_size: usize,
    /// Reassembly timeout
    pub reassembly_timeout: Duration,
    /// Enable fragment checksums
    pub enable_checksums: bool,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        let header_overhead = std::mem::size_of::<FragmentHeader>() + 8; // 8 bytes for bincode overhead
        Self {
            mtu: DEFAULT_MTU,
            header_overhead,
            max_fragment_size: DEFAULT_MTU - header_overhead,
            reassembly_timeout: DEFAULT_REASSEMBLY_TIMEOUT,
            enable_checksums: true,
        }
    }
}

impl FragmentationConfig {
    /// Create config with custom MTU
    pub fn with_mtu(mtu: usize) -> Self {
        let mut config = Self::default();
        config.mtu = mtu;
        config.max_fragment_size = mtu.saturating_sub(config.header_overhead);
        config
    }

    /// Calculate number of fragments needed for packet size
    pub fn calculate_fragment_count(&self, packet_size: usize) -> u16 {
        ((packet_size + self.max_fragment_size - 1) / self.max_fragment_size) as u16
    }

    /// Check if packet needs fragmentation
    pub fn needs_fragmentation(&self, packet_size: usize) -> bool {
        packet_size > self.max_fragment_size
    }
}

/// Packet fragmentation engine
#[derive(Debug)]
pub struct PacketFragmenter {
    config: FragmentationConfig,
    next_packet_id: u32,
}

impl PacketFragmenter {
    /// Create a new packet fragmenter
    pub fn new(config: FragmentationConfig) -> Self {
        Self {
            config,
            next_packet_id: 1,
        }
    }

    /// Fragment a packet into smaller pieces
    pub fn fragment_packet(&mut self, packet: &[u8]) -> Result<Vec<Fragment>, FragmentationError> {
        if packet.is_empty() {
            return Err(FragmentationError::EmptyPacket);
        }

        // Check if fragmentation is needed
        if !self.config.needs_fragmentation(packet.len()) {
            // Return single fragment for small packets
            let header = FragmentHeader::new(self.get_next_packet_id(), 0, 1, packet.len() as u16);
            let mut fragment = Fragment::new(header, packet.to_vec());
            
            if self.config.enable_checksums {
                fragment.header.checksum = FragmentHeader::calculate_checksum(&fragment.payload);
            }
            
            return Ok(vec![fragment]);
        }

        let packet_id = self.get_next_packet_id();
        let total_fragments = self.config.calculate_fragment_count(packet.len());
        let mut fragments = Vec::new();

        for fragment_id in 0..total_fragments {
            let start_offset = fragment_id as usize * self.config.max_fragment_size;
            let end_offset = std::cmp::min(
                start_offset + self.config.max_fragment_size, 
                packet.len()
            );
            
            let payload = packet[start_offset..end_offset].to_vec();
            let mut header = FragmentHeader::new(
                packet_id, 
                fragment_id, 
                total_fragments, 
                payload.len() as u16
            );

            if self.config.enable_checksums {
                header.checksum = FragmentHeader::calculate_checksum(&payload);
            }

            fragments.push(Fragment::new(header, payload));
        }

        Ok(fragments)
    }

    /// Get next available packet ID
    fn get_next_packet_id(&mut self) -> u32 {
        let id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        id
    }

    /// Get current configuration
    pub fn config(&self) -> &FragmentationConfig {
        &self.config
    }
}

/// Errors that can occur during fragmentation
#[derive(Debug, thiserror::Error)]
pub enum FragmentationError {
    #[error("Cannot fragment empty packet")]
    EmptyPacket,
    #[error("Packet too large to fragment: {size} bytes")]
    PacketTooLarge { size: usize },
    #[error("Invalid fragment size: {size}")]
    InvalidFragmentSize { size: usize },
    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_header_creation() {
        let header = FragmentHeader::new(123, 0, 3, 1400);
        assert_eq!(header.packet_id, 123);
        assert_eq!(header.fragment_id, 0);
        assert_eq!(header.total_fragments, 3);
        assert_eq!(header.fragment_size, 1400);
        assert!(header.has_more_fragments());
        assert!(!header.is_last_fragment());
    }

    #[test]
    fn test_last_fragment() {
        let header = FragmentHeader::new(123, 2, 3, 500);
        assert!(!header.has_more_fragments());
        assert!(header.is_last_fragment());
    }

    #[test]
    fn test_fragmentation_config() {
        let config = FragmentationConfig::with_mtu(1500);
        assert_eq!(config.mtu, 1500);
        assert!(config.max_fragment_size < 1500);
    }

    #[test]
    fn test_no_fragmentation_needed() {
        let config = FragmentationConfig::default();
        let mut fragmenter = PacketFragmenter::new(config.clone());
        
        let small_packet = vec![0u8; 100];
        let fragments = fragmenter.fragment_packet(&small_packet).unwrap();
        
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header.total_fragments, 1);
        assert_eq!(fragments[0].payload.len(), 100);
    }

    #[test]
    fn test_fragmentation_needed() {
        let config = FragmentationConfig::with_mtu(600);
        let mut fragmenter = PacketFragmenter::new(config.clone());
        
        let large_packet = vec![0u8; 2000];
        let fragments = fragmenter.fragment_packet(&large_packet).unwrap();
        
        assert!(fragments.len() > 1);
        
        // Verify fragment ordering and IDs
        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.header.fragment_id, i as u16);
            assert_eq!(fragment.header.total_fragments, fragments.len() as u16);
        }
        
        // Verify last fragment flags
        let last_fragment = fragments.last().unwrap();
        assert!(last_fragment.header.is_last_fragment());
        assert!(!last_fragment.header.has_more_fragments());
    }

    #[test]
    fn test_fragment_validation() {
        let mut header = FragmentHeader::new(1, 0, 1, 10);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        header.checksum = FragmentHeader::calculate_checksum(&payload);
        
        let fragment = Fragment::new(header, payload);
        assert!(fragment.validate());
    }

    #[test]
    fn test_empty_packet_error() {
        let config = FragmentationConfig::default();
        let mut fragmenter = PacketFragmenter::new(config);
        
        let result = fragmenter.fragment_packet(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FragmentationError::EmptyPacket));
    }
}