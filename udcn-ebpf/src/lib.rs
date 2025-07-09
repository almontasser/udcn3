#![no_std]

// This file exists to enable the library target and contains testable PIT logic.

use udcn_common::{PitEntry, PitStats, FaceInfo, MAX_ADDITIONAL_FACES};
use udcn_common::{PIT_STATE_ACTIVE, PIT_STATE_SATISFIED, PIT_STATE_EXPIRED};

/// PIT logic that can be tested independently of eBPF infrastructure
pub mod pit_logic {
    use super::*;

    /// Validate PIT entry creation parameters
    pub fn validate_pit_entry_params(name_hash: u64, face_id: u32, _nonce: u32, expiry_time: u64) -> Result<(), &'static str> {
        if name_hash == 0 {
            return Err("Name hash cannot be zero");
        }
        if face_id == 0 {
            return Err("Face ID cannot be zero");
        }
        if expiry_time == 0 {
            return Err("Expiry time cannot be zero");
        }
        Ok(())
    }

    /// Check if a PIT entry is expired based on current time
    pub fn is_pit_entry_expired(entry: &PitEntry, current_time: u64) -> bool {
        current_time > entry.expiry_time
    }

    /// Calculate time until expiry for a PIT entry
    pub fn time_until_expiry(entry: &PitEntry, current_time: u64) -> Result<u64, &'static str> {
        if current_time > entry.expiry_time {
            Err("Entry already expired")
        } else {
            Ok(entry.expiry_time - current_time)
        }
    }

    /// Check if Interest aggregation is possible
    pub fn can_aggregate_interest(existing_entry: &PitEntry, face_id: u32, nonce: u32) -> AggregationResult {
        // Same face, check nonce
        if existing_entry.incoming_face == face_id {
            if existing_entry.nonce == nonce {
                return AggregationResult::Duplicate;
            } else {
                return AggregationResult::SameFaceDifferentNonce;
            }
        }

        // Different face, check if we can add to additional faces
        if existing_entry.additional_faces_count < MAX_ADDITIONAL_FACES as u8 {
            AggregationResult::NewFace
        } else {
            AggregationResult::TooManyFaces
        }
    }

    /// Result of Interest aggregation check
    #[derive(Debug, PartialEq)]
    pub enum AggregationResult {
        /// Duplicate Interest (same face, same nonce)
        Duplicate,
        /// Same face but different nonce (retransmission)
        SameFaceDifferentNonce,
        /// New face for aggregation
        NewFace,
        /// Too many faces to aggregate
        TooManyFaces,
    }

    /// Simulate PIT entry update for Interest aggregation
    pub fn update_pit_entry_for_aggregation(entry: &mut PitEntry, face_id: u32, nonce: u32, expiry_time: u64) -> Result<(), &'static str> {
        match can_aggregate_interest(entry, face_id, nonce) {
            AggregationResult::SameFaceDifferentNonce => {
                entry.interest_count += 1;
                entry.nonce = nonce;
                entry.expiry_time = expiry_time;
                Ok(())
            }
            AggregationResult::NewFace => {
                entry.interest_count += 1;
                entry.expiry_time = expiry_time;
                entry.additional_faces_count += 1;
                Ok(())
            }
            AggregationResult::Duplicate => Err("Duplicate Interest"),
            AggregationResult::TooManyFaces => Err("Too many faces"),
        }
    }

    /// Check if face is valid for PIT operations
    pub fn is_face_valid(face_info: &FaceInfo) -> bool {
        face_info.face_id != 0 && (face_info.state & udcn_common::FACE_STATE_UP) != 0
    }

    /// Update PIT statistics for various operations
    pub fn update_stats_for_operation(stats: &mut PitStats, operation: PitOperation) {
        match operation {
            PitOperation::Insertion => {
                stats.insertions += 1;
                stats.entries_created += 1;
                stats.active_entries += 1;
            }
            PitOperation::Lookup => {
                stats.lookups += 1;
            }
            PitOperation::Satisfaction => {
                stats.entries_satisfied += 1;
                stats.deletions += 1;
                stats.active_entries = stats.active_entries.saturating_sub(1);
            }
            PitOperation::Expiration => {
                stats.entries_expired += 1;
                stats.deletions += 1;
                stats.active_entries = stats.active_entries.saturating_sub(1);
            }
            PitOperation::Aggregation => {
                stats.interests_aggregated += 1;
            }
            PitOperation::Cleanup => {
                stats.cleanups += 1;
            }
        }
    }

    /// PIT operation types for statistics
    #[derive(Debug, Clone, Copy)]
    pub enum PitOperation {
        Insertion,
        Lookup,
        Satisfaction,
        Expiration,
        Aggregation,
        Cleanup,
    }

    /// Validate PIT entry state transitions
    pub fn validate_state_transition(from: u8, to: u8) -> Result<(), &'static str> {
        match (from, to) {
            (PIT_STATE_ACTIVE, PIT_STATE_SATISFIED) => Ok(()),
            (PIT_STATE_ACTIVE, PIT_STATE_EXPIRED) => Ok(()),
            (PIT_STATE_SATISFIED, PIT_STATE_EXPIRED) => Ok(()),
            _ => Err("Invalid state transition"),
        }
    }

    /// Calculate hash for name (simplified version for testing)
    pub fn calculate_name_hash(name_bytes: &[u8]) -> u64 {
        let mut hash: u64 = 5381; // djb2 hash algorithm
        let max_len = if name_bytes.len() > 32 { 32 } else { name_bytes.len() };
        
        for &byte in name_bytes.iter().take(max_len) {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u64);
        }
        
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::pit_logic::*;

    fn create_test_pit_entry(name_hash: u64, face_id: u32, nonce: u32) -> PitEntry {
        let current_time = 1000000000;
        PitEntry {
            name_hash,
            incoming_face: face_id,
            nonce,
            expiry_time: current_time + 5000000000,
            created_time: current_time,
            interest_count: 1,
            state: PIT_STATE_ACTIVE,
            additional_faces_count: 0,
            _padding: [0; 2],
        }
    }

    fn create_test_face_info(face_id: u32) -> FaceInfo {
        FaceInfo {
            face_id,
            face_type: udcn_common::FACE_TYPE_ETHERNET,
            state: udcn_common::FACE_STATE_UP,
            ifindex: 1,
            mac_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ip_addr: [0; 16],
            port: 0,
            last_activity: 1000000000,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            _padding: [0; 6],
        }
    }

    #[test]
    fn test_pit_entry_validation() {
        // Valid parameters
        assert!(validate_pit_entry_params(0x123456, 42, 0xDEADBEEF, 1000000000).is_ok());
        
        // Invalid parameters
        assert!(validate_pit_entry_params(0, 42, 0xDEADBEEF, 1000000000).is_err());
        assert!(validate_pit_entry_params(0x123456, 0, 0xDEADBEEF, 1000000000).is_err());
        assert!(validate_pit_entry_params(0x123456, 42, 0xDEADBEEF, 0).is_err());
    }

    #[test]
    fn test_pit_entry_expiration() {
        let entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        let current_time = 1000000000;
        
        // Not expired
        assert!(!is_pit_entry_expired(&entry, current_time + 3000000000));
        
        // Expired
        assert!(is_pit_entry_expired(&entry, current_time + 6000000000));
    }

    #[test]
    fn test_time_until_expiry() {
        let entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        let current_time = 1000000000;
        
        // Still active
        let result = time_until_expiry(&entry, current_time + 2000000000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3000000000);
        
        // Already expired
        let result = time_until_expiry(&entry, current_time + 6000000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_interest_aggregation_same_face() {
        let entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        
        // Same face, same nonce (duplicate)
        let result = can_aggregate_interest(&entry, 42, 0xDEADBEEF);
        assert_eq!(result, AggregationResult::Duplicate);
        
        // Same face, different nonce (retransmission)
        let result = can_aggregate_interest(&entry, 42, 0xCAFEBABE);
        assert_eq!(result, AggregationResult::SameFaceDifferentNonce);
    }

    #[test]
    fn test_interest_aggregation_different_face() {
        let entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        
        // Different face (new aggregation)
        let result = can_aggregate_interest(&entry, 84, 0xCAFEBABE);
        assert_eq!(result, AggregationResult::NewFace);
    }

    #[test]
    fn test_interest_aggregation_too_many_faces() {
        let mut entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        entry.additional_faces_count = MAX_ADDITIONAL_FACES as u8;
        
        // Try to add one more face
        let result = can_aggregate_interest(&entry, 84, 0xCAFEBABE);
        assert_eq!(result, AggregationResult::TooManyFaces);
    }

    #[test]
    fn test_pit_entry_update_for_aggregation() {
        let mut entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        let original_count = entry.interest_count;
        
        // Same face, different nonce
        let result = update_pit_entry_for_aggregation(&mut entry, 42, 0xCAFEBABE, 2000000000);
        assert!(result.is_ok());
        assert_eq!(entry.interest_count, original_count + 1);
        assert_eq!(entry.nonce, 0xCAFEBABE);
        assert_eq!(entry.expiry_time, 2000000000);
        
        // New face
        let result = update_pit_entry_for_aggregation(&mut entry, 84, 0x12345678, 3000000000);
        assert!(result.is_ok());
        assert_eq!(entry.interest_count, original_count + 2);
        assert_eq!(entry.additional_faces_count, 1);
    }

    #[test]
    fn test_face_validation() {
        let face_info = create_test_face_info(42);
        assert!(is_face_valid(&face_info));
        
        // Invalid face (ID = 0)
        let mut invalid_face = face_info;
        invalid_face.face_id = 0;
        assert!(!is_face_valid(&invalid_face));
        
        // Invalid face (down state)
        let mut invalid_face = face_info;
        invalid_face.state = udcn_common::FACE_STATE_DOWN;
        assert!(!is_face_valid(&invalid_face));
    }

    #[test]
    fn test_pit_stats_updates() {
        let mut stats = PitStats::new();
        
        // Test insertion
        update_stats_for_operation(&mut stats, PitOperation::Insertion);
        assert_eq!(stats.insertions, 1);
        assert_eq!(stats.entries_created, 1);
        assert_eq!(stats.active_entries, 1);
        
        // Test lookup
        update_stats_for_operation(&mut stats, PitOperation::Lookup);
        assert_eq!(stats.lookups, 1);
        
        // Test satisfaction
        update_stats_for_operation(&mut stats, PitOperation::Satisfaction);
        assert_eq!(stats.entries_satisfied, 1);
        assert_eq!(stats.deletions, 1);
        assert_eq!(stats.active_entries, 0);
        
        // Test aggregation
        update_stats_for_operation(&mut stats, PitOperation::Aggregation);
        assert_eq!(stats.interests_aggregated, 1);
    }

    #[test]
    fn test_state_transitions() {
        // Valid transitions
        assert!(validate_state_transition(PIT_STATE_ACTIVE, PIT_STATE_SATISFIED).is_ok());
        assert!(validate_state_transition(PIT_STATE_ACTIVE, PIT_STATE_EXPIRED).is_ok());
        assert!(validate_state_transition(PIT_STATE_SATISFIED, PIT_STATE_EXPIRED).is_ok());
        
        // Invalid transitions
        assert!(validate_state_transition(PIT_STATE_SATISFIED, PIT_STATE_ACTIVE).is_err());
        assert!(validate_state_transition(PIT_STATE_EXPIRED, PIT_STATE_ACTIVE).is_err());
    }

    #[test]
    fn test_name_hash_calculation() {
        let name1 = b"test/name/component";
        let name2 = b"test/name/component";
        let name3 = b"different/name";
        
        let hash1 = calculate_name_hash(name1);
        let hash2 = calculate_name_hash(name2);
        let hash3 = calculate_name_hash(name3);
        
        // Same names should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different names should produce different hashes
        assert_ne!(hash1, hash3);
        
        // Hash should be non-zero for non-empty names
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_pit_entry_lifecycle() {
        let name_hash = 0x123456789ABCDEF0;
        let face_id = 42;
        let nonce = 0xDEADBEEF;
        let current_time = 1000000000;
        
        let mut entry = create_test_pit_entry(name_hash, face_id, nonce);
        entry.created_time = current_time;
        entry.expiry_time = current_time + 5000000000;
        
        // Initial state
        assert_eq!(entry.state, PIT_STATE_ACTIVE);
        assert_eq!(entry.created_time, current_time);
        
        // During active period
        let check_time = current_time + 2000000000;
        assert!(!is_pit_entry_expired(&entry, check_time));
        
        // After expiration
        let expired_time = current_time + 6000000000;
        assert!(is_pit_entry_expired(&entry, expired_time));
        
        // State transition to expired
        assert!(validate_state_transition(entry.state, PIT_STATE_EXPIRED).is_ok());
        entry.state = PIT_STATE_EXPIRED;
        assert_eq!(entry.state, PIT_STATE_EXPIRED);
    }

    #[test]
    fn test_pit_memory_management() {
        let mut entry = create_test_pit_entry(0x123456, 42, 0xDEADBEEF);
        
        // Test additional faces limit
        entry.additional_faces_count = 3;
        assert!(entry.additional_faces_count <= MAX_ADDITIONAL_FACES as u8);
        
        // Test cleanup simulation
        entry.additional_faces_count = 0;
        assert_eq!(entry.additional_faces_count, 0);
    }

    #[test]
    fn test_pit_cleanup_constants() {
        // Test that constants are reasonable
        assert!(udcn_common::PIT_ENTRY_TIMEOUT_NS > 0);
        assert!(udcn_common::PIT_ENTRY_TIMEOUT_NS <= 30_000_000_000); // Max 30 seconds
        assert!(udcn_common::MAX_PIT_ENTRIES > 0);
        assert!(udcn_common::MAX_PIT_ENTRIES <= 65536); // Reasonable limit
        assert!(udcn_common::MAX_ADDITIONAL_FACES > 0);
        assert!(udcn_common::MAX_ADDITIONAL_FACES <= 16); // Reasonable limit
    }
}
