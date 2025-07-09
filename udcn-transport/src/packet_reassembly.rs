use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, Instant};
use crate::packet_fragmentation::{Fragment, DEFAULT_REASSEMBLY_TIMEOUT};

/// Reassembly state for a single packet
#[derive(Debug)]
struct ReassemblyEntry {
    /// Fragments received so far, indexed by fragment_id
    fragments: BTreeMap<u16, Fragment>,
    /// Total number of fragments expected
    total_fragments: u16,
    /// Timestamp when first fragment was received
    first_fragment_time: Instant,
    /// Size of reassembled packet so far
    current_size: usize,
    /// Expected total size (calculated from fragments)
    expected_size: Option<usize>,
}

impl ReassemblyEntry {
    /// Create a new reassembly entry
    fn new(fragment: Fragment) -> Self {
        let total_fragments = fragment.header.total_fragments;
        let mut fragments = BTreeMap::new();
        let current_size = fragment.payload.len();
        
        fragments.insert(fragment.header.fragment_id, fragment);
        
        Self {
            fragments,
            total_fragments,
            first_fragment_time: Instant::now(),
            current_size,
            expected_size: None,
        }
    }

    /// Add a fragment to this reassembly entry
    fn add_fragment(&mut self, fragment: Fragment) -> Result<(), ReassemblyError> {
        let fragment_id = fragment.header.fragment_id;
        
        // Validate fragment belongs to this packet
        if fragment.header.total_fragments != self.total_fragments {
            return Err(ReassemblyError::FragmentMismatch {
                expected_total: self.total_fragments,
                received_total: fragment.header.total_fragments,
            });
        }

        // Check for duplicate fragments
        if self.fragments.contains_key(&fragment_id) {
            return Err(ReassemblyError::DuplicateFragment { fragment_id });
        }

        // Validate fragment
        if !fragment.validate() {
            return Err(ReassemblyError::InvalidFragment { fragment_id });
        }

        self.current_size += fragment.payload.len();
        self.fragments.insert(fragment_id, fragment);
        
        Ok(())
    }

    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total_fragments as usize &&
        self.fragments.keys().collect::<Vec<_>>() == 
            (0..self.total_fragments).collect::<Vec<_>>().iter().collect::<Vec<_>>()
    }

    /// Check if entry has expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.first_fragment_time.elapsed() > timeout
    }

    /// Reassemble the complete packet from fragments
    fn reassemble(&self) -> Result<Vec<u8>, ReassemblyError> {
        if !self.is_complete() {
            return Err(ReassemblyError::IncompletePacket {
                received: self.fragments.len(),
                expected: self.total_fragments as usize,
            });
        }

        let mut packet = Vec::with_capacity(self.current_size);
        
        // Fragments are already ordered by BTreeMap key (fragment_id)
        for fragment in self.fragments.values() {
            packet.extend_from_slice(&fragment.payload);
        }

        Ok(packet)
    }
}

/// Configuration for packet reassembly
#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    /// Maximum time to wait for all fragments
    pub reassembly_timeout: Duration,
    /// Maximum number of concurrent reassembly operations
    pub max_concurrent_reassemblies: usize,
    /// Enable strict fragment ordering validation
    pub strict_ordering: bool,
    /// Maximum packet size after reassembly
    pub max_reassembled_size: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            reassembly_timeout: DEFAULT_REASSEMBLY_TIMEOUT,
            max_concurrent_reassemblies: 1000,
            strict_ordering: true,
            max_reassembled_size: 1024 * 1024, // 1MB
        }
    }
}

/// Statistics for reassembly operations
#[derive(Debug, Default, Clone)]
pub struct ReassemblyStats {
    /// Total fragments received
    pub fragments_received: u64,
    /// Total packets successfully reassembled
    pub packets_reassembled: u64,
    /// Total fragments dropped due to errors
    pub fragments_dropped: u64,
    /// Total reassembly operations that timed out
    pub reassembly_timeouts: u64,
    /// Total duplicate fragments received
    pub duplicate_fragments: u64,
    /// Current number of active reassembly operations
    pub active_reassemblies: usize,
    /// Total bytes reassembled
    pub bytes_reassembled: u64,
}

impl ReassemblyStats {
    /// Calculate reassembly success rate
    pub fn success_rate(&self) -> f64 {
        if self.fragments_received == 0 {
            return 0.0;
        }
        self.packets_reassembled as f64 / (self.packets_reassembled + self.reassembly_timeouts) as f64
    }

    /// Calculate fragment loss rate
    pub fn fragment_loss_rate(&self) -> f64 {
        if self.fragments_received == 0 {
            return 0.0;
        }
        self.fragments_dropped as f64 / self.fragments_received as f64
    }
}

/// Packet reassembly engine
#[derive(Debug)]
pub struct PacketReassembler {
    config: ReassemblyConfig,
    reassembly_table: HashMap<u32, ReassemblyEntry>,
    stats: ReassemblyStats,
    last_cleanup: Instant,
}

impl PacketReassembler {
    /// Create a new packet reassembler
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            reassembly_table: HashMap::new(),
            stats: ReassemblyStats::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Process an incoming fragment
    pub fn process_fragment(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, ReassemblyError> {
        self.stats.fragments_received += 1;
        
        // Validate fragment
        if !fragment.validate() {
            self.stats.fragments_dropped += 1;
            return Err(ReassemblyError::InvalidFragment { 
                fragment_id: fragment.header.fragment_id 
            });
        }

        let packet_id = fragment.header.packet_id;
        
        // Check if we have room for new reassembly operations
        if self.reassembly_table.len() >= self.config.max_concurrent_reassemblies {
            self.cleanup_expired_entries();
            
            if self.reassembly_table.len() >= self.config.max_concurrent_reassemblies {
                self.stats.fragments_dropped += 1;
                return Err(ReassemblyError::TooManyReassemblies);
            }
        }

        // Handle single-fragment packets immediately
        if fragment.header.total_fragments == 1 {
            self.stats.packets_reassembled += 1;
            self.stats.bytes_reassembled += fragment.payload.len() as u64;
            return Ok(Some(fragment.payload));
        }

        // Add fragment to reassembly table
        match self.reassembly_table.get_mut(&packet_id) {
            Some(entry) => {
                // Add to existing reassembly
                match entry.add_fragment(fragment) {
                    Ok(()) => {
                        // Check if packet is now complete
                        if entry.is_complete() {
                            let packet = entry.reassemble()?;
                            self.reassembly_table.remove(&packet_id);
                            self.stats.packets_reassembled += 1;
                            self.stats.bytes_reassembled += packet.len() as u64;
                            self.update_active_count();
                            return Ok(Some(packet));
                        }
                    }
                    Err(ReassemblyError::DuplicateFragment { fragment_id }) => {
                        self.stats.duplicate_fragments += 1;
                        return Err(ReassemblyError::DuplicateFragment { fragment_id });
                    }
                    Err(e) => {
                        self.stats.fragments_dropped += 1;
                        return Err(e);
                    }
                }
            }
            None => {
                // Start new reassembly
                let entry = ReassemblyEntry::new(fragment);
                self.reassembly_table.insert(packet_id, entry);
                self.update_active_count();
            }
        }

        // Periodically cleanup expired entries
        if self.last_cleanup.elapsed() > Duration::from_secs(1) {
            self.cleanup_expired_entries();
        }

        Ok(None)
    }

    /// Force cleanup of expired reassembly entries
    pub fn cleanup_expired_entries(&mut self) {
        let timeout = self.config.reassembly_timeout;
        let expired_keys: Vec<u32> = self.reassembly_table
            .iter()
            .filter(|(_, entry)| entry.is_expired(timeout))
            .map(|(key, _)| *key)
            .collect();

        for key in expired_keys {
            self.reassembly_table.remove(&key);
            self.stats.reassembly_timeouts += 1;
        }

        self.update_active_count();
        self.last_cleanup = Instant::now();
    }

    /// Update active reassembly count in stats
    fn update_active_count(&mut self) {
        self.stats.active_reassemblies = self.reassembly_table.len();
    }

    /// Get current reassembly statistics
    pub fn stats(&self) -> &ReassemblyStats {
        &self.stats
    }

    /// Get current configuration
    pub fn config(&self) -> &ReassemblyConfig {
        &self.config
    }

    /// Check if a packet is currently being reassembled
    pub fn is_reassembling(&self, packet_id: u32) -> bool {
        self.reassembly_table.contains_key(&packet_id)
    }

    /// Get the progress of a reassembly operation
    pub fn reassembly_progress(&self, packet_id: u32) -> Option<(usize, usize)> {
        self.reassembly_table.get(&packet_id)
            .map(|entry| (entry.fragments.len(), entry.total_fragments as usize))
    }

    /// Clear all reassembly state (for testing/reset)
    pub fn clear(&mut self) {
        self.reassembly_table.clear();
        self.stats = ReassemblyStats::default();
        self.last_cleanup = Instant::now();
    }
}

/// Errors that can occur during reassembly
#[derive(Debug, thiserror::Error)]
pub enum ReassemblyError {
    #[error("Invalid fragment {fragment_id}")]
    InvalidFragment { fragment_id: u16 },
    
    #[error("Duplicate fragment {fragment_id}")]
    DuplicateFragment { fragment_id: u16 },
    
    #[error("Fragment mismatch: expected {expected_total} total fragments, got {received_total}")]
    FragmentMismatch { expected_total: u16, received_total: u16 },
    
    #[error("Incomplete packet: received {received} fragments, expected {expected}")]
    IncompletePacket { received: usize, expected: usize },
    
    #[error("Too many concurrent reassembly operations")]
    TooManyReassemblies,
    
    #[error("Reassembly timeout")]
    ReassemblyTimeout,
    
    #[error("Packet too large after reassembly: {size} bytes")]
    PacketTooLarge { size: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PacketFragmenter, FragmentationConfig, FragmentHeader, Fragment};

    #[test]
    fn test_single_fragment_reassembly() {
        let config = ReassemblyConfig::default();
        let mut reassembler = PacketReassembler::new(config);
        
        let mut header = FragmentHeader::new(1, 0, 1, 10);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        header.checksum = FragmentHeader::calculate_checksum(&payload);
        
        let fragment = Fragment::new(header, payload.clone());
        let result = reassembler.process_fragment(fragment).unwrap();
        
        assert_eq!(result, Some(payload));
        assert_eq!(reassembler.stats().packets_reassembled, 1);
    }

    #[test]
    fn test_multi_fragment_reassembly() {
        let frag_config = FragmentationConfig::with_mtu(600);
        let mut fragmenter = PacketFragmenter::new(frag_config);
        
        let original_packet = vec![42u8; 2000];
        let fragments = fragmenter.fragment_packet(&original_packet).unwrap();
        
        let config = ReassemblyConfig::default();
        let mut reassembler = PacketReassembler::new(config);
        
        let mut reassembled_packet = None;
        
        // Process fragments in order
        for fragment in fragments {
            if let Some(packet) = reassembler.process_fragment(fragment).unwrap() {
                reassembled_packet = Some(packet);
                break;
            }
        }
        
        assert!(reassembled_packet.is_some());
        assert_eq!(reassembled_packet.unwrap(), original_packet);
        assert_eq!(reassembler.stats().packets_reassembled, 1);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let frag_config = FragmentationConfig::with_mtu(600);
        let mut fragmenter = PacketFragmenter::new(frag_config);
        
        let original_packet = vec![123u8; 1500];
        let mut fragments = fragmenter.fragment_packet(&original_packet).unwrap();
        
        // Reverse fragment order to simulate out-of-order delivery
        fragments.reverse();
        
        let config = ReassemblyConfig::default();
        let mut reassembler = PacketReassembler::new(config);
        
        let mut reassembled_packet = None;
        
        for fragment in fragments {
            if let Some(packet) = reassembler.process_fragment(fragment).unwrap() {
                reassembled_packet = Some(packet);
                break;
            }
        }
        
        assert!(reassembled_packet.is_some());
        assert_eq!(reassembled_packet.unwrap(), original_packet);
    }

    #[test]
    fn test_duplicate_fragment_detection() {
        let config = ReassemblyConfig::default();
        let mut reassembler = PacketReassembler::new(config);
        
        let mut header = FragmentHeader::new(1, 0, 2, 500);
        let payload = vec![1u8; 500];
        header.checksum = FragmentHeader::calculate_checksum(&payload);
        
        let fragment1 = Fragment::new(header.clone(), payload.clone());
        let fragment2 = Fragment::new(header, payload);
        
        // First fragment should succeed
        let result1 = reassembler.process_fragment(fragment1);
        assert!(result1.is_ok());
        
        // Duplicate fragment should fail
        let result2 = reassembler.process_fragment(fragment2);
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), ReassemblyError::DuplicateFragment { .. }));
        assert_eq!(reassembler.stats().duplicate_fragments, 1);
    }

    #[test]
    fn test_reassembly_timeout() {
        let mut config = ReassemblyConfig::default();
        config.reassembly_timeout = Duration::from_millis(10);
        
        let mut reassembler = PacketReassembler::new(config);
        
        let mut header = FragmentHeader::new(1, 0, 2, 500);
        let payload = vec![1u8; 500];
        header.checksum = FragmentHeader::calculate_checksum(&payload);
        
        let fragment = Fragment::new(header, payload);
        
        // Add first fragment
        let result = reassembler.process_fragment(fragment);
        assert!(result.is_ok());
        assert_eq!(reassembler.stats().active_reassemblies, 1);
        
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));
        
        // Cleanup should remove expired entry
        reassembler.cleanup_expired_entries();
        assert_eq!(reassembler.stats().active_reassemblies, 0);
        assert_eq!(reassembler.stats().reassembly_timeouts, 1);
    }

    #[test]
    fn test_invalid_fragment() {
        let config = ReassemblyConfig::default();
        let mut reassembler = PacketReassembler::new(config);
        
        let mut header = FragmentHeader::new(1, 0, 1, 10);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        header.checksum = 0; // Invalid checksum
        
        let fragment = Fragment::new(header, payload);
        let result = reassembler.process_fragment(fragment);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ReassemblyError::InvalidFragment { .. }));
        assert_eq!(reassembler.stats().fragments_dropped, 1);
    }
}