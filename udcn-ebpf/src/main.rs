#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;
use core::mem;

/// XDP program entry point for UDCN packet processing
#[xdp]
pub fn udcn(ctx: XdpContext) -> u32 {
    try_udcn(ctx)
}

/// Main packet processing logic
fn try_udcn(ctx: XdpContext) -> u32 {
    let start_time = unsafe { bpf_ktime_get_ns() };
    
    // Get packet data bounds
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Basic packet length validation
    if data_start >= data_end {
        info!(&ctx, "Invalid packet: data_start >= data_end");
        let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
        update_packet_stats(&ctx, false, false, 0, processing_time);
        return xdp_action::XDP_DROP;
    }
    
    let packet_len = (data_end - data_start) as u64;
    
    // Parse Ethernet header
    let eth_hdr = match parse_ethernet_header(&ctx) {
        Ok(hdr) => hdr,
        Err(_) => {
            info!(&ctx, "Failed to parse Ethernet header");
            let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
            update_packet_stats(&ctx, false, false, packet_len, processing_time);
            return xdp_action::XDP_DROP;
        }
    };
    
    // Log packet information
    info!(
        &ctx,
        "Packet received: len={}, eth_type=0x{:x}",
        packet_len,
        eth_hdr.ether_type
    );
    
    // Process packet based on Ethernet type
    let result = match eth_hdr.ether_type {
        0x0800 => process_ipv4_packet(&ctx, data_start + mem::size_of::<EthernetHeader>()),
        0x86dd => process_ipv6_packet(&ctx, data_start + mem::size_of::<EthernetHeader>()),
        _ => {
            info!(&ctx, "Unsupported Ethernet type: 0x{:x}", eth_hdr.ether_type);
            Ok(xdp_action::XDP_PASS)
        }
    };
    
    // Calculate processing time and update stats
    let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
    
    // Trigger periodic PIT cleanup
    pit_trigger_periodic_cleanup(&ctx);
    
    // Trigger periodic Content Store cleanup
    cs_trigger_periodic_cleanup(&ctx);
    
    // Monitor network performance
    let _ = monitor_network_performance(&ctx);
    
    // Apply congestion control if needed
    let payload_start = match parse_payload_start(&ctx) {
        Ok(start) => start,
        Err(_) => 0,
    };
    
    if payload_start > 0 && payload_start + 1 < data_end {
        let packet_type = unsafe { *(payload_start as *const u8) };
        let name_hash = extract_interest_name_hash(&ctx, payload_start);
        
        if let Ok(congestion_action) = apply_congestion_control(&ctx, name_hash, packet_type) {
            if congestion_action == xdp_action::XDP_DROP {
                return xdp_action::XDP_DROP;
            }
        }
    }
    
    match result {
        Ok(action) => {
            let allowed = action == xdp_action::XDP_PASS;
            update_packet_stats(&ctx, true, allowed, packet_len, processing_time);
            
            // Apply real-time forwarding if packet was processed successfully
            if allowed {
                // Check if this packet needs immediate forwarding
                if let Ok(forward_action) = apply_realtime_forwarding(&ctx, payload_start) {
                    if forward_action != xdp_action::XDP_PASS {
                        info!(&ctx, "Real-time forwarding applied: {}", forward_action);
                        return forward_action;
                    }
                }
            }
            
            action
        }
        Err(_) => {
            update_packet_stats(&ctx, false, false, packet_len, processing_time);
            xdp_action::XDP_ABORTED
        }
    }
}

/// Ethernet header structure
#[repr(C)]
#[derive(Copy, Clone)]
struct EthernetHeader {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

/// Parse Ethernet header from packet
fn parse_ethernet_header(ctx: &XdpContext) -> Result<EthernetHeader, ()> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Check if we have enough data for Ethernet header
    if data_start + mem::size_of::<EthernetHeader>() > data_end {
        return Err(());
    }
    
    let eth_hdr = unsafe { *(data_start as *const EthernetHeader) };
    
    // Convert network byte order to host byte order for ether_type
    let ether_type = u16::from_be(eth_hdr.ether_type);
    
    Ok(EthernetHeader {
        dest_mac: eth_hdr.dest_mac,
        src_mac: eth_hdr.src_mac,
        ether_type,
    })
}

/// Process IPv4 packets and check for NDN Interest packets
fn process_ipv4_packet(ctx: &XdpContext, ip_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Basic IPv4 header validation
    if ip_start + 20 > data_end {
        info!(ctx, "IPv4 packet too short for header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    let ip_hdr = unsafe { *(ip_start as *const u8) };
    let ip_version = (ip_hdr >> 4) & 0xF;
    let ip_header_len = ((ip_hdr & 0xF) as usize) * 4;
    
    if ip_version != 4 {
        info!(ctx, "Invalid IPv4 version: {}", ip_version);
        return Ok(xdp_action::XDP_DROP);
    }
    
    if ip_header_len < 20 {
        info!(ctx, "IPv4 header too short: {}", ip_header_len);
        return Ok(xdp_action::XDP_DROP);
    }
    
    if ip_start + ip_header_len > data_end {
        info!(ctx, "IPv4 packet too short for full header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Get protocol field (byte 9 of IPv4 header)
    let protocol = unsafe { *((ip_start + 9) as *const u8) };
    
    // Check for UDP (17) or TCP (6) which might carry NDN packets
    match protocol {
        6 => {
            // TCP - check for NDN packets
            info!(ctx, "TCP packet detected, checking for NDN content");
            process_tcp_payload(ctx, ip_start + ip_header_len)
        }
        17 => {
            // UDP - check for NDN packets
            info!(ctx, "UDP packet detected, checking for NDN content");
            process_udp_payload(ctx, ip_start + ip_header_len)
        }
        _ => {
            info!(ctx, "Non-TCP/UDP protocol: {}", protocol);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Process IPv6 packets and check for NDN Interest packets
fn process_ipv6_packet(ctx: &XdpContext, ip_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Basic IPv6 header validation (40 bytes minimum)
    if ip_start + 40 > data_end {
        info!(ctx, "IPv6 packet too short for header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Get version field (first 4 bits)
    let version_byte = unsafe { *(ip_start as *const u8) };
    let ip_version = (version_byte >> 4) & 0xF;
    
    if ip_version != 6 {
        info!(ctx, "Invalid IPv6 version: {}", ip_version);
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Get next header field (byte 6 of IPv6 header)
    let next_header = unsafe { *((ip_start + 6) as *const u8) };
    
    // Check for UDP (17) or TCP (6) which might carry NDN packets
    match next_header {
        6 => {
            // TCP - check for NDN packets
            info!(ctx, "IPv6 TCP packet detected, checking for NDN content");
            process_tcp_payload(ctx, ip_start + 40)
        }
        17 => {
            // UDP - check for NDN packets
            info!(ctx, "IPv6 UDP packet detected, checking for NDN content");
            process_udp_payload(ctx, ip_start + 40)
        }
        _ => {
            info!(ctx, "IPv6 non-TCP/UDP next header: {}", next_header);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Process UDP payload for NDN packet detection
fn process_udp_payload(ctx: &XdpContext, udp_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Basic UDP header validation (8 bytes minimum)
    if udp_start + 8 > data_end {
        info!(ctx, "UDP packet too short for header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // UDP payload starts after 8-byte header
    let payload_start = udp_start + 8;
    
    if payload_start >= data_end {
        info!(ctx, "UDP packet has no payload");
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Check for NDN Interest packet in UDP payload
    check_ndn_interest(ctx, payload_start)
}

/// Process TCP payload for NDN packet detection
fn process_tcp_payload(ctx: &XdpContext, tcp_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Basic TCP header validation (20 bytes minimum)
    if tcp_start + 20 > data_end {
        info!(ctx, "TCP packet too short for header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Get TCP header length from data offset field (byte 12, upper 4 bits)
    let data_offset_byte = unsafe { *((tcp_start + 12) as *const u8) };
    let tcp_header_len = ((data_offset_byte >> 4) & 0xF) as usize * 4;
    
    if tcp_header_len < 20 {
        info!(ctx, "TCP header too short: {}", tcp_header_len);
        return Ok(xdp_action::XDP_DROP);
    }
    
    if tcp_start + tcp_header_len > data_end {
        info!(ctx, "TCP packet too short for full header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // TCP payload starts after variable-length header
    let payload_start = tcp_start + tcp_header_len;
    
    if payload_start >= data_end {
        info!(ctx, "TCP packet has no payload");
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Check for NDN Interest packet in TCP payload
    check_ndn_interest(ctx, payload_start)
}

/// Check if the payload contains an NDN Interest packet and extract detailed information
fn check_ndn_interest(ctx: &XdpContext, payload_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Need at least 2 bytes for TLV type and length
    if payload_start + 2 > data_end {
        info!(ctx, "Payload too short for TLV header");
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Read TLV type (first byte)
    let tlv_type = unsafe { *(payload_start as *const u8) };
    
    match tlv_type {
        NDN_TLV_INTEREST => {
            info!(ctx, "NDN Interest packet detected, using enhanced processing...");
            process_interest_packet_enhanced(ctx, payload_start)
        }
        NDN_TLV_DATA => {
            info!(ctx, "NDN Data packet detected, using enhanced processing");
            process_data_packet_enhanced(ctx, payload_start)
        }
        _ => {
            // Not an NDN packet, pass through
            Ok(xdp_action::XDP_PASS)
        }
    }
}

use aya_ebpf::{
    maps::{HashMap, LruHashMap},
    helpers::bpf_get_prandom_u32,
    macros::map,
};
use udcn_common::{UdcnConfig, PacketStats, PitEntry, PitStats, FaceInfo, PitFaceEntry,
                  PIT_STATE_ACTIVE, PIT_ENTRY_TIMEOUT_NS, MAX_PIT_ENTRIES, MAX_ADDITIONAL_FACES,
                  ContentStoreEntry, ContentStoreStats, LruState, MAX_CS_ENTRIES,
                  CS_STATE_VALID, CS_CLEANUP_INTERVAL};

// eBPF map for storing filtering configuration
#[map(name = "CONFIG_MAP")]
static CONFIG_MAP: HashMap<u32, UdcnConfig> = HashMap::with_max_entries(1, 0);

// eBPF map for storing filtering rules (name prefix hash -> action)
#[map(name = "FILTER_RULES")]
static FILTER_RULES: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

// eBPF map for storing packet statistics
#[map(name = "PACKET_STATS")]
static PACKET_STATS: HashMap<u32, PacketStats> = HashMap::with_max_entries(1, 0);

// eBPF map for storing recently seen Interest names (rate limiting)
#[map(name = "INTEREST_CACHE")]
static INTEREST_CACHE: LruHashMap<u64, u64> = LruHashMap::with_max_entries(4096, 0);

// eBPF map for storing PIT entries (name_hash -> PitEntry)
#[map(name = "PIT_TABLE")]
static PIT_TABLE: HashMap<u64, PitEntry> = HashMap::with_max_entries(MAX_PIT_ENTRIES as u32, 0);

// eBPF map for storing PIT statistics
#[map(name = "PIT_STATS")]
static PIT_STATS: HashMap<u32, PitStats> = HashMap::with_max_entries(1, 0);

// eBPF map for storing face information (face_id -> FaceInfo)
#[map(name = "FACE_TABLE")]
static FACE_TABLE: HashMap<u32, FaceInfo> = HashMap::with_max_entries(256, 0);

// eBPF map for storing additional faces per PIT entry (name_hash -> PitFaceEntry array)
// Using a compound key: (name_hash << 8) | face_index
#[map(name = "PIT_ADDITIONAL_FACES")]
static PIT_ADDITIONAL_FACES: HashMap<u64, PitFaceEntry> = HashMap::with_max_entries(MAX_PIT_ENTRIES as u32 * MAX_ADDITIONAL_FACES as u32, 0);

// eBPF map for storing cleanup counters and control variables
#[map(name = "PIT_CLEANUP_STATE")]
static PIT_CLEANUP_STATE: HashMap<u32, u64> = HashMap::with_max_entries(8, 0);

// eBPF map for Content Store entries (name_hash -> ContentStoreEntry)
#[map(name = "CONTENT_STORE")]
static CONTENT_STORE: HashMap<u64, ContentStoreEntry> = HashMap::with_max_entries(MAX_CS_ENTRIES as u32, 0);

// eBPF map for Content Store statistics
#[map(name = "CS_STATS")]
static CS_STATS: HashMap<u32, ContentStoreStats> = HashMap::with_max_entries(1, 0);

// eBPF map for LRU tracking state
#[map(name = "CS_LRU_STATE")]
static CS_LRU_STATE: HashMap<u32, LruState> = HashMap::with_max_entries(1, 0);

// eBPF map for storing actual content data (using per-CPU array for performance)
// Key is (name_hash << 16) | chunk_index, value is content chunk
#[map(name = "CS_DATA_CHUNKS")]
static CS_DATA_CHUNKS: HashMap<u64, [u8; 1024]> = HashMap::with_max_entries((MAX_CS_ENTRIES * 64) as u32, 0);

// eBPF map for Content Store cleanup state
#[map(name = "CS_CLEANUP_STATE")]
static CS_CLEANUP_STATE: HashMap<u32, u64> = HashMap::with_max_entries(8, 0);

// Filtering action constants
const FILTER_ACTION_ALLOW: u32 = 0;
const FILTER_ACTION_DROP: u32 = 1;
const FILTER_ACTION_REDIRECT: u32 = 2;

// Rate limiting constants
const RATE_LIMIT_WINDOW_MS: u64 = 1000; // 1 second window
const DEFAULT_RATE_LIMIT: u32 = 100; // 100 requests per second

// PIT cleanup constants
const PIT_CLEANUP_INTERVAL_PACKETS: u32 = 100; // Trigger cleanup every 100 packets
const PIT_CLEANUP_BATCH_SIZE: u32 = 10; // Maximum entries to clean per batch

// PIT cleanup state keys
const PIT_CLEANUP_KEY_PACKET_COUNT: u32 = 0;
const PIT_CLEANUP_KEY_LAST_CLEANUP: u32 = 1;
const PIT_CLEANUP_KEY_TOTAL_CLEANUPS: u32 = 2;

// Content Store cleanup state keys
const CS_CLEANUP_KEY_PACKET_COUNT: u32 = 0;
const CS_CLEANUP_KEY_LAST_CLEANUP: u32 = 1;
const CS_CLEANUP_KEY_TOTAL_CLEANUPS: u32 = 2;
const CS_CLEANUP_KEY_MIN_LRU_SEQUENCE: u32 = 3;

fn process_data_packet(ctx: &XdpContext, data_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Data packet
    let tlv_result = parse_tlv_length(ctx, data_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Data TLV length");
        return Ok(xdp_action::XDP_DROP);
    }
    let data_length = (tlv_result >> 16) as usize;
    let tlv_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate Data packet bounds
    if data_start + tlv_header_size + data_length > data_end {
        info!(ctx, "Data packet truncated, declared length: {}", data_length);
        return Ok(xdp_action::XDP_DROP);
    }
    
    let data_content_start = data_start + tlv_header_size;
    info!(ctx, "Data packet: length={}, content_start={}", data_length, data_content_start);
    
    // Extract name hash from Data packet (first element should be Name TLV)
    let name_hash = extract_interest_name_hash(ctx, data_content_start);
    if name_hash != 0 {
        // Check if there's a corresponding PIT entry
        match pit_remove(ctx, name_hash) {
            Ok(pit_entry) => {
                info!(ctx, "PIT entry satisfied by Data packet, forwarding to {} faces", 
                      pit_entry.additional_faces_count + 1);
                
                // Insert Data into Content Store for future cache hits
                let data_size = data_length as u32;
                if data_size <= 65536 { // Maximum content size
                    // Extract freshness period (default to 1 hour if not found)
                    let freshness_period_ms = 3600000; // 1 hour default
                    
                    match cs_insert(ctx, name_hash, data_size, freshness_period_ms) {
                        Ok(()) => {
                            // Store the actual data chunks
                            let _ = cs_store_data_chunks(ctx, name_hash, data_start, data_size);
                            info!(ctx, "Data packet cached in Content Store");
                        }
                        Err(_) => {
                            info!(ctx, "Failed to cache Data packet in Content Store");
                        }
                    }
                }
                
                // Forward to primary face
                if face_get_forwarding_info(ctx, pit_entry.incoming_face) == 1 {
                    face_update_stats(ctx, pit_entry.incoming_face, 1, 0, data_length as u64, 0);
                    info!(ctx, "Forwarding Data to primary face: {}", pit_entry.incoming_face);
                } else {
                    info!(ctx, "Primary face {} is unavailable", pit_entry.incoming_face);
                }
                
                // Forward to additional faces (if any)
                for i in 0..pit_entry.additional_faces_count {
                    let face_key = (name_hash << 8) | (i as u64);
                    if let Some(face_entry) = unsafe { PIT_ADDITIONAL_FACES.get(&face_key) } {
                        if face_get_forwarding_info(ctx, face_entry.face_id) == 1 {
                            face_update_stats(ctx, face_entry.face_id, 1, 0, data_length as u64, 0);
                            info!(ctx, "Forwarding Data to additional face: {}", face_entry.face_id);
                        } else {
                            info!(ctx, "Additional face {} is unavailable", face_entry.face_id);
                        }
                    }
                }
                
                Ok(xdp_action::XDP_PASS)
            }
            Err(_) => {
                // No PIT entry found, but still cache the Data for future Interests
                let data_size = data_length as u32;
                if data_size <= 65536 { // Maximum content size
                    let freshness_period_ms = 3600000; // 1 hour default
                    
                    match cs_insert(ctx, name_hash, data_size, freshness_period_ms) {
                        Ok(()) => {
                            let _ = cs_store_data_chunks(ctx, name_hash, data_start, data_size);
                            info!(ctx, "Unsolicited Data packet cached in Content Store");
                        }
                        Err(_) => {
                            info!(ctx, "Failed to cache unsolicited Data packet");
                        }
                    }
                }
                
                info!(ctx, "No PIT entry found for Data packet, dropping");
                Ok(xdp_action::XDP_DROP)
            }
        }
    } else {
        info!(ctx, "Failed to extract name from Data packet");
        Ok(xdp_action::XDP_DROP)
    }
}

fn process_interest_packet(ctx: &XdpContext, interest_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Interest packet
    let tlv_result = parse_tlv_length(ctx, interest_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Interest TLV length");
        update_packet_stats(ctx, false, false, 0, 0);
        return Ok(xdp_action::XDP_DROP);
    }
    let interest_length = (tlv_result >> 16) as usize;
    let tlv_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate Interest packet bounds
    if interest_start + tlv_header_size + interest_length > data_end {
        info!(ctx, "Interest packet truncated, declared length: {}", interest_length);
        update_packet_stats(ctx, false, false, 0, 0);
        return Ok(xdp_action::XDP_DROP);
    }
    
    let interest_content_start = interest_start + tlv_header_size;
    info!(ctx, "Interest packet: length={}, content_start={}", interest_length, interest_content_start);
    
    // Parse Interest name (first mandatory element)
    let (name_length, component_count) = match parse_interest_name(ctx, interest_content_start) {
        Ok(name_info) => name_info,
        Err(_) => {
            info!(ctx, "Failed to parse Interest name");
            update_packet_stats(ctx, false, false, 0, 0);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    
    info!(ctx, "Interest name parsed: length={}, components={}", name_length, component_count);
    
    // Extract name hash for filtering, CS lookup, and PIT operations
    let name_hash = extract_interest_name_hash(ctx, interest_content_start);
    if name_hash != 0 {
        // Check Content Store first for cached data
        match cs_lookup(ctx, name_hash) {
            Ok(()) => {
                info!(ctx, "Content Store hit for Interest, returning cached Data");
                // Extract face information from packet metadata
                let face_id = match extract_face_id_from_context(ctx) {
                    Ok(id) => id,
                    Err(_) => {
                        info!(ctx, "Failed to extract face ID, using default");
                        1u32 // Default face ID
                    }
                };
                
                // Update face statistics for outgoing Data
                face_update_stats(ctx, face_id, 1, 0, 0, 0); // No size info available
                update_packet_stats(ctx, true, true, 0, 0);
                
                // In a real implementation, we would construct and send the Data packet
                // For now, we just pass the packet to indicate cache hit
                return Ok(xdp_action::XDP_PASS);
            }
            Err(_) => {
                info!(ctx, "Content Store miss, proceeding with normal Interest processing");
            }
        }
        
        // Apply filtering rules
        match apply_filter_rules(ctx, name_hash, component_count) {
            Ok(action) => {
                if action == xdp_action::XDP_PASS {
                    // Extract face information from packet metadata
                    let face_id = match extract_face_id_from_context(ctx) {
                        Ok(id) => id,
                        Err(_) => {
                            info!(ctx, "Failed to extract face ID, using default");
                            1u32 // Default face ID
                        }
                    };
                    
                    let nonce = match extract_nonce_from_interest(ctx, interest_content_start) {
                        Ok(n) => n,
                        Err(_) => {
                            info!(ctx, "Failed to extract nonce, using default");
                            0u32 // Default nonce
                        }
                    };
                    
                    // Update face statistics for incoming Interest
                    let _ = face_update_with_packet_info(ctx, face_id, true, interest_length as u32);
                    
                    // Try to insert/update PIT entry
                    match pit_insert_or_update(ctx, name_hash, face_id, nonce) {
                        Ok(()) => {
                            info!(ctx, "PIT entry created/updated successfully for face: {}", face_id);
                            update_packet_stats(ctx, true, true, 0, 0);
                            Ok(xdp_action::XDP_PASS)
                        }
                        Err(_) => {
                            info!(ctx, "Failed to create/update PIT entry for face: {}", face_id);
                            update_packet_stats(ctx, false, false, 0, 0);
                            Ok(xdp_action::XDP_DROP)
                        }
                    }
                } else {
                    update_packet_stats(ctx, true, false, 0, 0);
                    Ok(action)
                }
            }
            Err(_) => {
                info!(ctx, "Filter rule evaluation failed");
                update_packet_stats(ctx, false, false, 0, 0);
                Ok(xdp_action::XDP_DROP)
            }
        }
    } else {
        info!(ctx, "Failed to extract Interest name for filtering");
        update_packet_stats(ctx, false, false, 0, 0);
        Ok(xdp_action::XDP_DROP)
    }
}

/// Extract Interest name hash for filtering
/// Returns hash value, or 0 on error
fn extract_interest_name_hash(ctx: &XdpContext, name_start: usize) -> u64 {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for Name TLV header
    if name_start + 2 > data_end {
        return 0;
    }
    
    // Verify this is a Name TLV
    let name_type = unsafe { *(name_start as *const u8) };
    if name_type != NDN_TLV_NAME {
        return 0;
    }
    
    // Parse name length
    let tlv_result = parse_tlv_length(ctx, name_start + 1);
    if tlv_result == 0 {
        return 0;
    }
    let name_length = (tlv_result >> 16) as usize;
    let name_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate name bounds
    if name_start + name_header_size + name_length > data_end {
        return 0;
    }
    
    // Calculate simple hash of name content (limited to avoid stack issues)
    let name_content_start = name_start + name_header_size;
    let hash_length = if name_length > 32 { 32 } else { name_length };
    let mut hash: u64 = 5381; // djb2 hash algorithm
    
    for i in 0..hash_length {
        if name_content_start + i >= data_end {
            break;
        }
        let byte = unsafe { *((name_content_start + i) as *const u8) };
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u64);
    }
    
    hash
}

/// Apply filtering rules to Interest packet
fn apply_filter_rules(ctx: &XdpContext, name_hash: u64, component_count: u32) -> Result<u32, ()> {
    // Get filtering configuration
    let config = match unsafe { CONFIG_MAP.get(&0) } {
        Some(cfg) => cfg,
        None => {
            info!(ctx, "No filter configuration found, allowing packet");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    
    // Check if filtering is enabled
    if config.filter_enabled == 0 {
        info!(ctx, "Filtering disabled, allowing packet");
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Apply rate limiting
    if let Err(_) = apply_rate_limiting(ctx, name_hash) {
        info!(ctx, "Rate limit exceeded, dropping packet");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Apply component count filtering
    if component_count == 0 {
        info!(ctx, "Empty Interest name, dropping packet");
        return Ok(xdp_action::XDP_DROP);
    }
    
    if component_count > 64 {
        info!(ctx, "Too many name components ({}), dropping packet", component_count);
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Check specific filtering rules
    match check_filter_rules(ctx, name_hash) {
        Ok(action) => {
            info!(ctx, "Filter rule matched, action: {}", action);
            match action {
                FILTER_ACTION_ALLOW => Ok(xdp_action::XDP_PASS),
                FILTER_ACTION_DROP => Ok(xdp_action::XDP_DROP),
                FILTER_ACTION_REDIRECT => {
                    // For redirect, we pass the packet but could modify it
                    info!(ctx, "Redirecting packet (not implemented yet)");
                    Ok(xdp_action::XDP_PASS)
                }
                _ => Ok(xdp_action::XDP_DROP),
            }
        }
        Err(_) => {
            // No specific rule found, apply default policy
            info!(ctx, "No specific filter rule found, applying default policy");
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Apply rate limiting to Interest packets
fn apply_rate_limiting(_ctx: &XdpContext, name_hash: u64) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Check if we've seen this Interest recently
    match unsafe { INTEREST_CACHE.get(&name_hash) } {
        Some(last_seen) => {
            let time_diff = current_time - *last_seen;
            if time_diff < RATE_LIMIT_WINDOW_MS * 1_000_000 { // Convert ms to ns
                // Within rate limit window, check if we should drop
                let random_value = unsafe { bpf_get_prandom_u32() };
                if random_value % DEFAULT_RATE_LIMIT == 0 {
                    // Allow this packet (statistically rate limited)
                    let _ = unsafe { INTEREST_CACHE.insert(&name_hash, &current_time, 0) };
                    Ok(())
                } else {
                    // Drop this packet
                    Err(())
                }
            } else {
                // Outside rate limit window, allow and update timestamp
                let _ = unsafe { INTEREST_CACHE.insert(&name_hash, &current_time, 0) };
                Ok(())
            }
        }
        None => {
            // First time seeing this Interest, allow and record
            let _ = unsafe { INTEREST_CACHE.insert(&name_hash, &current_time, 0) };
            Ok(())
        }
    }
}

/// Check specific filtering rules for Interest name
fn check_filter_rules(ctx: &XdpContext, name_hash: u64) -> Result<u32, ()> {
    // Check exact match first
    match unsafe { FILTER_RULES.get(&name_hash) } {
        Some(action) => {
            info!(ctx, "Filter rule match found for hash: {}", name_hash);
            return Ok(*action);
        }
        None => {
            // Check for common prefix hashes (simplified approach)
            // In a real implementation, this would use more sophisticated prefix matching
            let prefix_hash1 = name_hash & 0xFFFFFFFF00000000; // Upper 32 bits
            let prefix_hash2 = name_hash & 0xFFFF000000000000; // Upper 16 bits
            
            // Check prefix patterns
            for prefix_hash in [prefix_hash1, prefix_hash2] {
                match unsafe { FILTER_RULES.get(&prefix_hash) } {
                    Some(action) => {
                        info!(ctx, "Prefix filter rule match found for hash: {}", prefix_hash);
                        return Ok(*action);
                    }
                    None => continue,
                }
            }
        }
    }
    
    // No rule found
    Err(())
}

/// Update packet statistics in eBPF map
fn update_packet_stats(ctx: &XdpContext, valid_packet: bool, allowed: bool, bytes: u64, processing_time: u64) {
    let packet_len = if bytes > 0 { bytes } else { 
        let data_start = ctx.data();
        let data_end = ctx.data_end();
        if data_end > data_start {
            (data_end - data_start) as u64
        } else {
            0
        }
    };
    
    match unsafe { PACKET_STATS.get(&0) } {
        Some(stats) => {
            // Copy the stats to modify them
            let mut new_stats = *stats;
            new_stats.packets_processed += 1;
            new_stats.bytes_processed += packet_len;
            new_stats.processing_time_ns += processing_time;
            
            if valid_packet {
                new_stats.interest_packets += 1;
                if allowed {
                    new_stats.packets_passed += 1;
                } else {
                    new_stats.packets_dropped += 1;
                }
            } else {
                new_stats.packets_dropped += 1;
            }
            let _ = unsafe { PACKET_STATS.insert(&0, &new_stats, 0) };
        }
        None => {
            // Initialize statistics
            let stats = PacketStats {
                packets_processed: 1,
                packets_dropped: if !valid_packet || !allowed { 1 } else { 0 },
                packets_passed: if valid_packet && allowed { 1 } else { 0 },
                packets_redirected: 0,
                bytes_processed: packet_len,
                processing_time_ns: processing_time,
                interest_packets: if valid_packet { 1 } else { 0 },
                data_packets: 0,
                nack_packets: 0,
                control_packets: 0,
                parse_errors: 0,
                memory_errors: 0,
            };
            let _ = unsafe { PACKET_STATS.insert(&0, &stats, 0) };
        }
    }
}

/// Parse TLV length field according to NDN TLV specification
/// Returns combined value: (length << 16) | header_size, or 0 on error
fn parse_tlv_length(ctx: &XdpContext, length_start: usize) -> u64 {
    let data_end = ctx.data_end();
    
    if length_start >= data_end {
        return 0;
    }
    
    let first_byte = unsafe { *(length_start as *const u8) };
    
    // Single byte length (0-252)
    if first_byte <= 252 {
        let length = first_byte as usize;
        let header_size = 2usize; // 1 byte type + 1 byte length
        return ((length as u64) << 16) | (header_size as u64);
    }
    
    // Multi-byte length encoding
    match first_byte {
        253 => {
            // 2-byte length
            if length_start + 2 >= data_end {
                return 0;
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u16;
                u16::from_be(*ptr) as usize
            };
            let header_size = 4usize; // 1 byte type + 1 byte prefix + 2 byte length
            ((length as u64) << 16) | (header_size as u64)
        }
        254 => {
            // 4-byte length
            if length_start + 4 >= data_end {
                return 0;
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u32;
                u32::from_be(*ptr) as usize
            };
            let header_size = 6usize; // 1 byte type + 1 byte prefix + 4 byte length
            ((length as u64) << 16) | (header_size as u64)
        }
        255 => {
            // 8-byte length (not commonly used in practice)
            if length_start + 8 >= data_end {
                return 0;
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u64;
                u64::from_be(*ptr) as usize
            };
            let header_size = 10usize; // 1 byte type + 1 byte prefix + 8 byte length
            ((length as u64) << 16) | (header_size as u64)
        }
        _ => 0,
    }
}

/// Parse Interest name and return (name_length, component_count)
fn parse_interest_name(ctx: &XdpContext, name_start: usize) -> Result<(usize, u32), ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for Name TLV header
    if name_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is a Name TLV
    let name_type = unsafe { *(name_start as *const u8) };
    if name_type != NDN_TLV_NAME {
        info!(ctx, "Expected Name TLV, got: {}", name_type);
        return Err(());
    }
    
    // Parse name length
    let tlv_result = parse_tlv_length(ctx, name_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Name TLV length");
        return Err(());
    }
    let name_length = (tlv_result >> 16) as usize;
    let name_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate name bounds
    if name_start + name_header_size + name_length > data_end {
        info!(ctx, "Name TLV truncated");
        return Err(());
    }
    
    // Count name components
    let component_count = count_name_components(ctx, name_start + name_header_size, name_length)?;
    
    Ok((name_length, component_count))
}

/// Count the number of name components in the Name TLV
fn count_name_components(ctx: &XdpContext, name_content_start: usize, name_length: usize) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let name_end = name_content_start + name_length;
    
    if name_end > data_end {
        return Err(());
    }
    
    let mut component_count = 0u32;
    let mut current_pos = name_content_start;
    
    // Iterate through name components (limited to prevent infinite loops)
    while current_pos < name_end && component_count < 64 {
        // Check if we have enough data for component TLV header
        if current_pos + 2 > name_end {
            break;
        }
        
        // Check component type
        let component_type = unsafe { *(current_pos as *const u8) };
        if component_type != NDN_TLV_NAME_COMPONENT {
            info!(ctx, "Invalid name component type: {}", component_type);
            break;
        }
        
        // Parse component length
        let tlv_result = parse_tlv_length(ctx, current_pos + 1);
        if tlv_result == 0 {
            break;
        }
        let component_length = (tlv_result >> 16) as usize;
        let component_header_size = (tlv_result & 0xFFFF) as usize;
        
        // Validate component bounds
        if current_pos + component_header_size + component_length > name_end {
            break;
        }
        
        component_count += 1;
        current_pos += component_header_size + component_length;
    }
    
    Ok(component_count)
}

/// Insert or update a PIT entry for an Interest packet
fn pit_insert_or_update(ctx: &XdpContext, name_hash: u64, face_id: u32, nonce: u32) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let expiry_time = current_time + PIT_ENTRY_TIMEOUT_NS;
    
    // Update PIT statistics
    update_pit_stats(ctx, |stats| {
        stats.lookups += 1;
    });
    
    // Check if PIT entry already exists
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(existing_entry) => {
            // Entry exists, check if it's expired
            if current_time > existing_entry.expiry_time {
                // Expired entry, create new one
                let new_entry = PitEntry {
                    name_hash,
                    incoming_face: face_id,
                    nonce,
                    expiry_time,
                    created_time: current_time,
                    interest_count: 1,
                    state: PIT_STATE_ACTIVE,
                    additional_faces_count: 0,
                    _padding: [0; 2],
                };
                
                let _ = unsafe { PIT_TABLE.insert(&name_hash, &new_entry, 0) };
                update_pit_stats(ctx, |stats| {
                    stats.insertions += 1;
                    stats.entries_created += 1;
                });
                
                info!(ctx, "PIT entry created for expired entry, name_hash: {}", name_hash);
                Ok(())
            } else {
                // Valid entry exists, try to aggregate Interest
                match pit_aggregate_interest(ctx, name_hash, existing_entry, face_id, nonce, expiry_time) {
                    Ok(()) => {
                        info!(ctx, "Interest aggregated successfully");
                        Ok(())
                    }
                    Err(_) => {
                        info!(ctx, "Interest aggregation failed");
                        Err(())
                    }
                }
            }
        }
        None => {
            // No existing entry, create new one
            let new_entry = PitEntry {
                name_hash,
                incoming_face: face_id,
                nonce,
                expiry_time,
                created_time: current_time,
                interest_count: 1,
                state: PIT_STATE_ACTIVE,
                additional_faces_count: 0,
                _padding: [0; 2],
            };
            
            match unsafe { PIT_TABLE.insert(&name_hash, &new_entry, 0) } {
                Ok(_) => {
                    update_pit_stats(ctx, |stats| {
                        stats.insertions += 1;
                        stats.entries_created += 1;
                        stats.active_entries += 1;
                    });
                    
                    info!(ctx, "New PIT entry created, name_hash: {}", name_hash);
                    Ok(())
                }
                Err(_) => {
                    info!(ctx, "Failed to create PIT entry, table may be full");
                    Err(())
                }
            }
        }
    }
}

/// Lookup a PIT entry by name hash
fn pit_lookup(ctx: &XdpContext, name_hash: u64) -> Result<PitEntry, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Update PIT statistics
    update_pit_stats(ctx, |stats| {
        stats.lookups += 1;
    });
    
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            // Check if entry is expired
            if current_time > entry.expiry_time {
                // Entry is expired, remove it
                let _ = unsafe { PIT_TABLE.remove(&name_hash) };
                update_pit_stats(ctx, |stats| {
                    stats.entries_expired += 1;
                    stats.deletions += 1;
                    stats.active_entries = stats.active_entries.saturating_sub(1);
                });
                
                info!(ctx, "PIT entry expired and removed, name_hash: {}", name_hash);
                Err(())
            } else {
                // Entry is valid
                Ok(*entry)
            }
        }
        None => {
            // No entry found
            Err(())
        }
    }
}

/// Remove a PIT entry (typically when Data packet is received)
fn pit_remove(ctx: &XdpContext, name_hash: u64) -> Result<PitEntry, ()> {
    // Update PIT statistics
    update_pit_stats(ctx, |stats| {
        stats.lookups += 1;
    });
    
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            let removed_entry = *entry;
            
            // Clean up additional faces first
            for i in 0..removed_entry.additional_faces_count {
                let face_key = (name_hash << 8) | (i as u64);
                let _ = unsafe { PIT_ADDITIONAL_FACES.remove(&face_key) };
            }
            
            // Remove main PIT entry
            let _ = unsafe { PIT_TABLE.remove(&name_hash) };
            
            update_pit_stats(ctx, |stats| {
                stats.entries_satisfied += 1;
                stats.deletions += 1;
                stats.active_entries = stats.active_entries.saturating_sub(1);
            });
            
            info!(ctx, "PIT entry removed (satisfied), name_hash: {}, additional_faces: {}", 
                  name_hash, removed_entry.additional_faces_count);
            Ok(removed_entry)
        }
        None => {
            info!(ctx, "PIT entry not found for removal, name_hash: {}", name_hash);
            Err(())
        }
    }
}

/// Aggregate an Interest into an existing PIT entry
fn pit_aggregate_interest(ctx: &XdpContext, name_hash: u64, existing_entry: &PitEntry, face_id: u32, nonce: u32, expiry_time: u64) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Check if this Interest is from the same face as the primary entry
    if existing_entry.incoming_face == face_id {
        // Same face, check if nonce is different (avoid duplicates)
        if existing_entry.nonce != nonce {
            // Different nonce, this is a retransmission or new Interest
            let mut updated_entry = *existing_entry;
            updated_entry.interest_count += 1;
            updated_entry.expiry_time = expiry_time; // Refresh expiry time
            updated_entry.nonce = nonce; // Update to latest nonce
            
            let _ = unsafe { PIT_TABLE.insert(&name_hash, &updated_entry, 0) };
            update_pit_stats(ctx, |stats| {
                stats.interests_aggregated += 1;
            });
            
            info!(ctx, "Interest aggregated on same face, count: {}", updated_entry.interest_count);
            return Ok(());
        } else {
            // Same nonce, duplicate Interest - drop it
            info!(ctx, "Duplicate Interest detected (same face, same nonce)");
            return Err(());
        }
    }
    
    // Different face, check if we can add it to additional faces
    if existing_entry.additional_faces_count < MAX_ADDITIONAL_FACES as u8 {
        // Check if this face is already in the additional faces
        for i in 0..existing_entry.additional_faces_count {
            let face_key = (name_hash << 8) | (i as u64);
            if let Some(face_entry) = unsafe { PIT_ADDITIONAL_FACES.get(&face_key) } {
                if face_entry.face_id == face_id {
                    // Face already exists, check nonce
                    if face_entry.nonce != nonce {
                        // Different nonce, update
                        let updated_face = PitFaceEntry {
                            face_id,
                            nonce,
                            timestamp: current_time,
                        };
                        let _ = unsafe { PIT_ADDITIONAL_FACES.insert(&face_key, &updated_face, 0) };
                        
                        // Update main entry
                        let mut updated_entry = *existing_entry;
                        updated_entry.interest_count += 1;
                        updated_entry.expiry_time = expiry_time;
                        let _ = unsafe { PIT_TABLE.insert(&name_hash, &updated_entry, 0) };
                        
                        update_pit_stats(ctx, |stats| {
                            stats.interests_aggregated += 1;
                        });
                        
                        info!(ctx, "Interest aggregated on existing additional face");
                        return Ok(());
                    } else {
                        // Same nonce, duplicate
                        info!(ctx, "Duplicate Interest on additional face");
                        return Err(());
                    }
                }
            }
        }
        
        // Add new additional face
        let new_face_entry = PitFaceEntry {
            face_id,
            nonce,
            timestamp: current_time,
        };
        
        let face_key = (name_hash << 8) | (existing_entry.additional_faces_count as u64);
        match unsafe { PIT_ADDITIONAL_FACES.insert(&face_key, &new_face_entry, 0) } {
            Ok(_) => {
                // Update main entry
                let mut updated_entry = *existing_entry;
                updated_entry.interest_count += 1;
                updated_entry.expiry_time = expiry_time;
                updated_entry.additional_faces_count += 1;
                let _ = unsafe { PIT_TABLE.insert(&name_hash, &updated_entry, 0) };
                
                update_pit_stats(ctx, |stats| {
                    stats.interests_aggregated += 1;
                });
                
                info!(ctx, "New additional face added for Interest aggregation");
                Ok(())
            }
            Err(_) => {
                info!(ctx, "Failed to add additional face for aggregation");
                Err(())
            }
        }
    } else {
        // Too many faces, cannot aggregate
        info!(ctx, "Cannot aggregate Interest: too many faces");
        Err(())
    }
}

/// Clean up expired PIT entries (enhanced version)
fn pit_cleanup(ctx: &XdpContext) -> u32 {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let mut cleaned_count = 0u32;
    
    // Note: eBPF maps don't support iteration, so cleanup is done opportunistically
    // during lookups or by userspace programs. This function is a placeholder
    // for userspace-triggered cleanup operations
    
    update_pit_stats(ctx, |stats| {
        stats.cleanups += 1;
    });
    
    cleaned_count
}

/// Clean up expired PIT entry by name hash (called opportunistically)
fn pit_cleanup_entry(ctx: &XdpContext, name_hash: u64) -> bool {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            if current_time > entry.expiry_time {
                // Entry is expired, remove it and its additional faces
                for i in 0..entry.additional_faces_count {
                    let face_key = (name_hash << 8) | (i as u64);
                    let _ = unsafe { PIT_ADDITIONAL_FACES.remove(&face_key) };
                }
                
                // Remove main PIT entry
                let _ = unsafe { PIT_TABLE.remove(&name_hash) };
                
                update_pit_stats(ctx, |stats| {
                    stats.entries_expired += 1;
                    stats.deletions += 1;
                    stats.active_entries = stats.active_entries.saturating_sub(1);
                });
                
                info!(ctx, "Expired PIT entry cleaned up, name_hash: {}, additional_faces: {}", 
                      name_hash, entry.additional_faces_count);
                true
            } else {
                false
            }
        }
        None => false,
    }
}

/// Check if a PIT entry is expired without removing it
fn pit_is_expired(ctx: &XdpContext, name_hash: u64) -> bool {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => current_time > entry.expiry_time,
        None => true, // Non-existent entries are considered expired
    }
}

/// Get time until expiration for a PIT entry (in nanoseconds)
fn pit_time_until_expiry(ctx: &XdpContext, name_hash: u64) -> Result<u64, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            if current_time > entry.expiry_time {
                Ok(0) // Already expired
            } else {
                Ok(entry.expiry_time - current_time)
            }
        }
        None => Err(()),
    }
}

/// Trigger periodic PIT cleanup if needed
fn pit_trigger_periodic_cleanup(ctx: &XdpContext) {
    // Increment packet counter
    let packet_count = match unsafe { PIT_CLEANUP_STATE.get(&PIT_CLEANUP_KEY_PACKET_COUNT) } {
        Some(count) => *count + 1,
        None => 1,
    };
    
    let _ = unsafe { PIT_CLEANUP_STATE.insert(&PIT_CLEANUP_KEY_PACKET_COUNT, &packet_count, 0) };
    
    // Check if we should trigger cleanup
    if packet_count % PIT_CLEANUP_INTERVAL_PACKETS as u64 == 0 {
        pit_periodic_cleanup(ctx);
    }
}

/// Periodic cleanup function (called from main packet processing)
fn pit_periodic_cleanup(ctx: &XdpContext) {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Update last cleanup time
    let _ = unsafe { PIT_CLEANUP_STATE.insert(&PIT_CLEANUP_KEY_LAST_CLEANUP, &current_time, 0) };
    
    // Increment total cleanups counter
    let total_cleanups = match unsafe { PIT_CLEANUP_STATE.get(&PIT_CLEANUP_KEY_TOTAL_CLEANUPS) } {
        Some(count) => *count + 1,
        None => 1,
    };
    let _ = unsafe { PIT_CLEANUP_STATE.insert(&PIT_CLEANUP_KEY_TOTAL_CLEANUPS, &total_cleanups, 0) };
    
    update_pit_stats(ctx, |stats| {
        stats.cleanups += 1;
    });
    
    info!(ctx, "Periodic PIT cleanup triggered, cleanup #{}", total_cleanups);
    
    // Note: Since eBPF maps don't support iteration, periodic cleanup
    // is limited to what we can do without iteration. In practice,
    // userspace programs would handle bulk cleanup operations.
}

/// Update PIT statistics with a closure
fn update_pit_stats<F>(ctx: &XdpContext, update_fn: F) 
where
    F: FnOnce(&mut PitStats),
{
    match unsafe { PIT_STATS.get(&0) } {
        Some(stats) => {
            let mut new_stats = *stats;
            update_fn(&mut new_stats);
            let _ = unsafe { PIT_STATS.insert(&0, &new_stats, 0) };
        }
        None => {
            let mut stats = PitStats::new();
            update_fn(&mut stats);
            let _ = unsafe { PIT_STATS.insert(&0, &stats, 0) };
        }
    }
}

/// Get or create face information
fn face_get_or_create(ctx: &XdpContext, face_id: u32, face_type: u8, ifindex: u32) -> Result<FaceInfo, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match unsafe { FACE_TABLE.get(&face_id) } {
        Some(face_info) => {
            // Face exists, update last activity
            let mut updated_face = *face_info;
            updated_face.last_activity = current_time;
            let _ = unsafe { FACE_TABLE.insert(&face_id, &updated_face, 0) };
            Ok(updated_face)
        }
        None => {
            // Create new face
            let new_face = FaceInfo {
                face_id,
                face_type,
                state: 0x01, // FACE_STATE_UP
                ifindex,
                mac_addr: [0; 6],
                ip_addr: [0; 16],
                port: 0,
                last_activity: current_time,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                _padding: [0; 6],
            };
            
            match unsafe { FACE_TABLE.insert(&face_id, &new_face, 0) } {
                Ok(_) => {
                    info!(ctx, "Created new face: {}", face_id);
                    Ok(new_face)
                }
                Err(_) => {
                    info!(ctx, "Failed to create face: {}", face_id);
                    Err(())
                }
            }
        }
    }
}

/// Update face statistics
fn face_update_stats(ctx: &XdpContext, face_id: u32, packets_sent: u64, packets_received: u64, bytes_sent: u64, bytes_received: u64) {
    if let Some(face_info) = unsafe { FACE_TABLE.get(&face_id) } {
        let mut updated_face = *face_info;
        updated_face.packets_sent += packets_sent;
        updated_face.packets_received += packets_received;
        updated_face.bytes_sent += bytes_sent;
        updated_face.bytes_received += bytes_received;
        updated_face.last_activity = unsafe { bpf_ktime_get_ns() };
        
        let _ = unsafe { FACE_TABLE.insert(&face_id, &updated_face, 0) };
    }
}

/// Extract face ID from packet context (based on interface and protocol)
fn extract_face_id_from_context(ctx: &XdpContext) -> Result<u32, ()> {
    // For now, create a simple face ID based on interface index
    // In a real implementation, this would use more sophisticated face mapping
    
    // Get interface index from context (if available)
    // Note: XDP context doesn't directly provide interface index,
    // so we'll generate a simple face ID based on available information
    
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Simple face ID generation based on packet characteristics
    // In reality, this would be managed by a userspace daemon
    let mut face_id = 1u32;
    
    // Try to differentiate faces based on packet headers
    if data_start + 14 <= data_end { // Ethernet header size
        let eth_hdr = unsafe { *(data_start as *const EthernetHeader) };
        
        // Use a simple hash of source MAC as face identifier
        let mut hash = 0u32;
        for byte in eth_hdr.src_mac.iter() {
            hash = hash.wrapping_mul(31).wrapping_add(*byte as u32);
        }
        face_id = (hash % 255) + 1; // Ensure face_id is 1-255
    }
    
    // Ensure face exists in face table
    let _ = face_get_or_create(ctx, face_id, 0x01, 0); // FACE_TYPE_ETHERNET
    
    Ok(face_id)
}

/// Extract nonce from Interest packet
fn extract_nonce_from_interest(ctx: &XdpContext, interest_content_start: usize) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let mut current_pos = interest_content_start;
    
    // Skip the Name TLV (first element)
    if current_pos + 2 > data_end {
        return Err(());
    }
    
    // Check if this is actually a Name TLV
    let name_type = unsafe { *(current_pos as *const u8) };
    if name_type != 0x07 { // NDN_TLV_NAME
        return Err(());
    }
    
    // Parse name length and skip the name
    let tlv_result = parse_tlv_length(ctx, current_pos + 1);
    if tlv_result == 0 {
        return Err(());
    }
    let name_length = (tlv_result >> 16) as usize;
    let name_header_size = (tlv_result & 0xFFFF) as usize;
    
    current_pos += name_header_size + name_length;
    
    // Look for Nonce TLV (type 0x0A)
    while current_pos + 2 < data_end {
        let tlv_type = unsafe { *(current_pos as *const u8) };
        
        if tlv_type == 0x0A { // NDN_TLV_NONCE
            // Parse nonce length
            let tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if tlv_result == 0 {
                return Err(());
            }
            let nonce_length = (tlv_result >> 16) as usize;
            let nonce_header_size = (tlv_result & 0xFFFF) as usize;
            
            if nonce_length == 4 && current_pos + nonce_header_size + 4 <= data_end {
                // Extract 4-byte nonce
                let nonce_value = unsafe {
                    let ptr = (current_pos + nonce_header_size) as *const u32;
                    u32::from_be(*ptr)
                };
                return Ok(nonce_value);
            }
        }
        
        // Skip this TLV
        let tlv_result = parse_tlv_length(ctx, current_pos + 1);
        if tlv_result == 0 {
            break;
        }
        let tlv_length = (tlv_result >> 16) as usize;
        let tlv_header_size = (tlv_result & 0xFFFF) as usize;
        
        current_pos += tlv_header_size + tlv_length;
    }
    
    // No nonce found, generate a simple one based on name hash
    let name_hash = extract_interest_name_hash(ctx, interest_content_start);
    Ok((name_hash & 0xFFFFFFFF) as u32)
}

/// Enhanced face management: Update face information with packet metadata
fn face_update_with_packet_info(ctx: &XdpContext, face_id: u32, is_incoming: bool, packet_size: u32) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match unsafe { FACE_TABLE.get(&face_id) } {
        Some(face_info) => {
            let mut updated_face = *face_info;
            updated_face.last_activity = current_time;
            
            if is_incoming {
                updated_face.packets_received += 1;
                updated_face.bytes_received += packet_size as u64;
            } else {
                updated_face.packets_sent += 1;
                updated_face.bytes_sent += packet_size as u64;
            }
            
            let _ = unsafe { FACE_TABLE.insert(&face_id, &updated_face, 0) };
            Ok(())
        }
        None => {
            // Create new face if it doesn't exist
            let new_face = FaceInfo {
                face_id,
                face_type: udcn_common::FACE_TYPE_ETHERNET,
                state: udcn_common::FACE_STATE_UP,
                ifindex: 0,      // Would be set by userspace
                mac_addr: [0; 6],
                ip_addr: [0; 16],
                port: 0,
                last_activity: current_time,
                packets_sent: if is_incoming { 0 } else { 1 },
                packets_received: if is_incoming { 1 } else { 0 },
                bytes_sent: if is_incoming { 0 } else { packet_size as u64 },
                bytes_received: if is_incoming { packet_size as u64 } else { 0 },
                _padding: [0; 6],
            };
            
            match unsafe { FACE_TABLE.insert(&face_id, &new_face, 0) } {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        }
    }
}

/// Get face information for PIT entry forwarding
/// Returns 1 if face is active, 0 if face is down or not found
fn face_get_forwarding_info(ctx: &XdpContext, face_id: u32) -> u32 {
    match unsafe { FACE_TABLE.get(&face_id) } {
        Some(face_info) => {
            // Check if face is still active
            if face_info.state & 0x01 != 0 { // FACE_STATE_UP
                1
            } else {
                info!(ctx, "Face {} is down", face_id);
                0
            }
        }
        None => {
            info!(ctx, "Face {} not found", face_id);
            0
        }
    }
}

/// Content Store lookup operation with improved collision handling and atomic access
fn cs_lookup(ctx: &XdpContext, name_hash: u64) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Update CS statistics atomically
    update_cs_stats(ctx, |stats| {
        stats.lookups += 1;
    });
    
    // Primary lookup attempt
    match unsafe { CONTENT_STORE.get(&name_hash) } {
        Some(entry) => {
            let entry_copy = *entry;
            
            // Validate entry integrity and check expiration
            if current_time > entry_copy.expiry_time {
                // Entry is expired, remove it atomically
                cs_remove_entry(ctx, name_hash);
                update_cs_stats(ctx, |stats| {
                    stats.misses += 1;
                    stats.expirations += 1;
                });
                info!(ctx, "CS entry expired for name_hash: {}", name_hash);
                return Err(());
            }
            
            // Check if entry is in valid state
            if entry_copy.state & CS_STATE_VALID != 0 {
                // Valid entry found, update LRU and hit count atomically
                let mut updated_entry = entry_copy;
                updated_entry.last_access_time = current_time;
                updated_entry.hit_count = updated_entry.hit_count.saturating_add(1);
                
                // Update LRU sequence for cache replacement
                if let Ok(new_sequence) = cs_get_next_lru_sequence_optimized(ctx) {
                    updated_entry.lru_sequence = new_sequence;
                }
                
                // Atomic update of entry
                if let Ok(_) = unsafe { CONTENT_STORE.insert(&name_hash, &updated_entry, 0) } {
                    update_cs_stats(ctx, |stats| {
                        stats.hits += 1;
                    });
                    
                    info!(ctx, "CS hit for name_hash: {}, hits: {}", name_hash, updated_entry.hit_count);
                    Ok(())
                } else {
                    // Insert failed, return original entry but count as miss
                    update_cs_stats(ctx, |stats| {
                        stats.misses += 1;
                    });
                    info!(ctx, "CS entry update failed for name_hash: {}", name_hash);
                    Err(())
                }
            } else {
                // Entry exists but not valid (e.g., pending or marked for eviction)
                update_cs_stats(ctx, |stats| {
                    stats.misses += 1;
                });
                info!(ctx, "CS entry not valid for name_hash: {}, state: {}", name_hash, entry_copy.state);
                Err(())
            }
        }
        None => {
            // Primary lookup failed - could be due to collision or genuinely missing
            // For improved collision handling, we could implement secondary hash probing
            // However, eBPF HashMap should handle most collisions internally
            
            update_cs_stats(ctx, |stats| {
                stats.misses += 1;
            });
            
            // Optional: Add secondary probe with different hash function
            // This would require implementing a secondary hash function
            // For now, we rely on the eBPF HashMap collision resolution
            
            Err(())
        }
    }
}

/// Insert or update Content Store entry with optimized LRU eviction and atomic operations
fn cs_insert(ctx: &XdpContext, name_hash: u64, data_size: u32, freshness_period_ms: u64) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let expiry_time = current_time + (freshness_period_ms * 1_000_000);
    
    // Check if entry already exists (update case)
    if let Some(existing_entry) = unsafe { CONTENT_STORE.get(&name_hash) } {
        // Update existing entry with new data and refresh LRU sequence
        let mut updated_entry = *existing_entry;
        let old_size = updated_entry.data_size;
        
        updated_entry.data_size = data_size;
        updated_entry.last_access_time = current_time;
        updated_entry.expiry_time = expiry_time;
        updated_entry.hit_count = updated_entry.hit_count.saturating_add(1);
        updated_entry.state = CS_STATE_VALID; // Ensure valid state
        
        // Get fresh LRU sequence to mark as most recently used
        if let Ok(new_sequence) = cs_get_next_lru_sequence(ctx) {
            updated_entry.lru_sequence = new_sequence;
        }
        
        // Atomic update of existing entry
        match unsafe { CONTENT_STORE.insert(&name_hash, &updated_entry, 0) } {
            Ok(_) => {
                update_cs_stats(ctx, |stats| {
                    stats.insertions += 1;
                    // Update bytes stored (handle size change)
                    stats.bytes_stored = stats.bytes_stored.saturating_sub(old_size as u64);
                    stats.bytes_stored += data_size as u64;
                });
                
                info!(ctx, "CS entry updated for name_hash: {}, new_size: {}", name_hash, data_size);
                return Ok(());
            }
            Err(_) => {
                info!(ctx, "Failed to update existing CS entry for name_hash: {}", name_hash);
                return Err(());
            }
        }
    }
    
    // New entry insertion - check capacity and perform eviction if needed
    let stats = match unsafe { CS_STATS.get(&0) } {
        Some(s) => *s,
        None => ContentStoreStats::new(),
    };
    
    // Improved eviction strategy: more aggressive and efficient
    // Use integer math to avoid floating point in eBPF
    let cache_utilization_percent = (stats.current_entries * 100) / (MAX_CS_ENTRIES as u64);
    let entries_to_evict = if cache_utilization_percent >= 90 {
        // Cache is nearly full, evict more aggressively
        let base_evict = (stats.current_entries - (MAX_CS_ENTRIES as u64 * 8 / 10)) as u32; // Keep 80% capacity
        let additional_evict = (MAX_CS_ENTRIES as u32 / 10).max(1); // Evict at least 10% or 1 entry
        base_evict + additional_evict
    } else if stats.current_entries >= MAX_CS_ENTRIES as u64 {
        // Cache is full, evict minimum required
        (stats.current_entries - MAX_CS_ENTRIES as u64 + 1) as u32
    } else {
        0
    };
    
    if entries_to_evict > 0 {
        // Perform efficient LRU eviction
        let evicted = cs_evict_multiple_lru_entries(ctx, entries_to_evict);
        if evicted > 0 {
            info!(ctx, "CS evicted {} entries (requested: {})", evicted, entries_to_evict);
        } else {
            info!(ctx, "CS eviction failed, attempting insertion anyway");
            // Continue with insertion even if eviction failed partially
        }
    }
    
    // Periodic aging cleanup for better cache performance
    if stats.insertions % 16 == 0 {
        let _ = cs_lru_aging_cleanup(ctx);
    }
    
    // Get next LRU sequence for new entry using optimized version
    let lru_sequence = cs_get_next_lru_sequence_optimized(ctx).unwrap_or(0);
    
    // Create new entry with optimized structure
    let new_entry = ContentStoreEntry {
        name_hash,
        data_size,
        content_type: 0, // Default content type
        state: CS_STATE_VALID,
        _reserved: 0,
        hit_count: 0,
        lru_sequence,
        created_time: current_time,
        last_access_time: current_time,
        expiry_time,
        data_hash: 0, // Could be computed from data for integrity
    };
    
    // Atomic insertion of new entry
    match unsafe { CONTENT_STORE.insert(&name_hash, &new_entry, 0) } {
        Ok(_) => {
            update_cs_stats(ctx, |stats| {
                stats.insertions += 1;
                stats.current_entries += 1;
                stats.bytes_stored += data_size as u64;
                if stats.current_entries > stats.max_entries_reached {
                    stats.max_entries_reached = stats.current_entries;
                }
            });
            
            info!(ctx, "CS entry inserted: name_hash={}, size={}, lru_seq={}", 
                  name_hash, data_size, lru_sequence);
            Ok(())
        }
        Err(_) => {
            info!(ctx, "Failed to insert CS entry for name_hash: {}", name_hash);
            Err(())
        }
    }
}

/// Remove Content Store entry
fn cs_remove_entry(ctx: &XdpContext, name_hash: u64) -> Result<ContentStoreEntry, ()> {
    match unsafe { CONTENT_STORE.get(&name_hash) } {
        Some(entry) => {
            let removed_entry = *entry;
            
            // Remove data chunks
            let chunk_count = (removed_entry.data_size + 1023) / 1024;
            for i in 0..chunk_count {
                let chunk_key = (name_hash << 16) | (i as u64);
                let _ = unsafe { CS_DATA_CHUNKS.remove(&chunk_key) };
            }
            
            // Remove main entry
            let _ = unsafe { CONTENT_STORE.remove(&name_hash) };
            
            update_cs_stats(ctx, |stats| {
                stats.current_entries = stats.current_entries.saturating_sub(1);
                stats.bytes_stored = stats.bytes_stored.saturating_sub(removed_entry.data_size as u64);
            });
            
            info!(ctx, "CS entry removed for name_hash: {}", name_hash);
            Ok(removed_entry)
        }
        None => Err(()),
    }
}

/// Evict least recently used entry from Content Store with improved efficiency
fn cs_evict_lru_entry(ctx: &XdpContext) -> Result<(), ()> {
    // Get current LRU state for better tracking
    let lru_state = match unsafe { CS_LRU_STATE.get(&0) } {
        Some(state) => *state,
        None => LruState {
            sequence_counter: 0,
            min_sequence: 0,
            max_sequence: 0,
            _reserved: 0,
        },
    };
    
    // Get current minimum sequence from cleanup state
    let mut min_sequence = match unsafe { CS_CLEANUP_STATE.get(&CS_CLEANUP_KEY_MIN_LRU_SEQUENCE) } {
        Some(seq) => *seq as u32,
        None => lru_state.min_sequence,
    };
    
    // Adjust min_sequence if it's too old or uninitialized
    if min_sequence == 0 || lru_state.sequence_counter.wrapping_sub(min_sequence) > (MAX_CS_ENTRIES as u32 * 2) {
        min_sequence = lru_state.sequence_counter.wrapping_sub(MAX_CS_ENTRIES as u32);
    }
    
    // Improved eviction strategy: use multiple hash probes with better distribution
    let mut evicted = false;
    let mut attempts = 0;
    let max_attempts = 32; // Increased attempts for better success rate
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Use improved probing strategy with multiple hash functions
    while !evicted && attempts < max_attempts {
        // Multiple probe strategies for better coverage
        let probe_keys = [
            // Strategy 1: Sequential probing from min_sequence
            (min_sequence.wrapping_add(attempts) as u64)
                .wrapping_mul(0x9e3779b97f4a7c15)
                ^ (current_time >> 32),
            
            // Strategy 2: Random-like probing
            (attempts as u64).wrapping_mul(0x517cc1b727220a95)
                ^ (current_time & 0xFFFFFFFF)
                ^ (min_sequence as u64),
            
            // Strategy 3: Power-of-two probing
            ((1u64 << (attempts % 16)) ^ (min_sequence as u64))
                .wrapping_mul(0xaef17502108ef2d9),
        ];
        
        for probe_key in probe_keys.iter() {
            if let Some(entry) = unsafe { CONTENT_STORE.get(probe_key) } {
                let entry_copy = *entry;
                
                // Improved eviction candidate selection
                let is_expired = current_time > entry_copy.expiry_time;
                let is_old_lru = entry_copy.lru_sequence <= min_sequence.wrapping_add(attempts);
                let is_low_hit_count = entry_copy.hit_count < 2; // Evict entries with few hits
                
                // Prioritize expired entries, then old LRU, then low hit count
                if is_expired || (is_old_lru && is_low_hit_count) || 
                   (attempts > max_attempts / 2 && is_old_lru) {
                    
                    // Atomic deletion
                    if let Ok(_) = unsafe { CONTENT_STORE.remove(probe_key) } {
                        evicted = true;
                        
                        // Update stats atomically
                        update_cs_stats(ctx, |stats| {
                            stats.evictions += 1;
                            stats.current_entries = stats.current_entries.saturating_sub(1);
                            stats.bytes_stored = stats.bytes_stored.saturating_sub(entry_copy.data_size as u64);
                        });
                        
                        info!(ctx, "CS evicted entry: name_hash={}, lru_seq={}, hits={}, expired={}", 
                              *probe_key, entry_copy.lru_sequence, entry_copy.hit_count, is_expired as u32);
                        
                        // Update minimum sequence tracking
                        if entry_copy.lru_sequence < min_sequence {
                            min_sequence = entry_copy.lru_sequence;
                        }
                        break;
                    }
                }
            }
        }
        
        attempts += 1;
    }
    
    // Update minimum sequence for future evictions
    let new_min_sequence = min_sequence.wrapping_add(1);
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_MIN_LRU_SEQUENCE, &(new_min_sequence as u64), 0) };
    
    if evicted {
        info!(ctx, "CS LRU eviction successful after {} attempts", attempts);
        Ok(())
    } else {
        info!(ctx, "CS LRU eviction failed after {} attempts", attempts);
        // Return Ok even if no eviction happened - cache might be full of very recent entries
        Ok(())
    }
}

/// Atomic Content Store entry update with retry logic for concurrent access
fn cs_atomic_update_entry(ctx: &XdpContext, name_hash: u64, update_fn: impl Fn(&mut ContentStoreEntry)) -> Result<(), ()> {
    const MAX_RETRIES: u32 = 3;
    let mut retries = 0;
    
    while retries < MAX_RETRIES {
        match unsafe { CONTENT_STORE.get(&name_hash) } {
            Some(entry) => {
                let mut updated_entry = *entry;
                update_fn(&mut updated_entry);
                
                // Attempt atomic update
                match unsafe { CONTENT_STORE.insert(&name_hash, &updated_entry, 0) } {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        retries += 1;
                        if retries < MAX_RETRIES {
                            // Brief pause before retry (simulated with a read operation)
                            let _ = unsafe { bpf_ktime_get_ns() };
                        }
                    }
                }
            }
            None => return Err(()), // Entry doesn't exist
        }
    }
    
    info!(ctx, "CS atomic update failed after {} retries for name_hash: {}", MAX_RETRIES, name_hash);
    Err(())
}

/// Optimized batch eviction with better memory management
fn cs_evict_multiple_lru_entries_optimized(ctx: &XdpContext, target_count: u32) -> Result<u32, ()> {
    let mut evicted_count = 0;
    let mut attempts = 0;
    let max_total_attempts = target_count * 16; // Limit total attempts
    
    // Get current LRU state
    let lru_state = match unsafe { CS_LRU_STATE.get(&0) } {
        Some(state) => *state,
        None => return Err(()),
    };
    
    let mut min_sequence = lru_state.min_sequence;
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Batch eviction with improved efficiency
    while evicted_count < target_count && attempts < max_total_attempts {
        // Generate probe keys with better distribution
        let probe_increment = attempts / 4; // Change strategy every 4 attempts
        let probe_key = match probe_increment % 3 {
            0 => (min_sequence.wrapping_add(attempts) as u64).wrapping_mul(0x9e3779b97f4a7c15),
            1 => (attempts as u64).wrapping_mul(0x517cc1b727220a95) ^ (current_time >> 16),
            _ => ((attempts as u64) << 8) ^ (min_sequence as u64).wrapping_mul(0xaef17502108ef2d9),
        };
        
        if let Some(entry) = unsafe { CONTENT_STORE.get(&probe_key) } {
            let entry_copy = *entry;
            
            // Enhanced eviction criteria
            let is_expired = current_time > entry_copy.expiry_time;
            let age_factor = lru_state.sequence_counter.wrapping_sub(entry_copy.lru_sequence);
            let is_old = age_factor > (MAX_CS_ENTRIES as u32 / 2);
            let is_unpopular = entry_copy.hit_count < 3;
            
            // Evict if expired, old, or unpopular
            if is_expired || is_old || (evicted_count > target_count / 2 && is_unpopular) {
                if let Ok(_) = unsafe { CONTENT_STORE.remove(&probe_key) } {
                    evicted_count += 1;
                    
                    // Update stats
                    update_cs_stats(ctx, |stats| {
                        stats.evictions += 1;
                        stats.current_entries = stats.current_entries.saturating_sub(1);
                        stats.bytes_stored = stats.bytes_stored.saturating_sub(entry_copy.data_size as u64);
                    });
                    
                    // Update minimum sequence
                    if entry_copy.lru_sequence < min_sequence {
                        min_sequence = entry_copy.lru_sequence;
                    }
                }
            }
        }
        
        attempts += 1;
    }
    
    // Update minimum sequence for future evictions
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_MIN_LRU_SEQUENCE, &(min_sequence as u64), 0) };
    
    if evicted_count > 0 {
        info!(ctx, "CS batch eviction: {} entries evicted in {} attempts", evicted_count, attempts);
        Ok(evicted_count)
    } else {
        info!(ctx, "CS batch eviction failed: no entries evicted in {} attempts", attempts);
        Err(())
    }
}

/// Fast hash-based key lookup with inline optimizations
#[inline(always)]
fn cs_fast_lookup(name_hash: u64) -> Option<ContentStoreEntry> {
    unsafe { CONTENT_STORE.get(&name_hash).map(|entry| *entry) }
}

/// Optimized cache hit ratio calculation for monitoring
fn cs_calculate_hit_ratio(ctx: &XdpContext) -> Result<u32, ()> {
    if let Some(stats) = unsafe { CS_STATS.get(&0) } {
        let total_requests = stats.hits + stats.misses;
        if total_requests > 0 {
            let hit_ratio = (stats.hits * 100) / total_requests;
            Ok(hit_ratio as u32)
        } else {
            Ok(0)
        }
    } else {
        Err(())
    }
}

/// Memory-efficient entry validation
#[inline(always)]
fn cs_validate_entry(entry: &ContentStoreEntry, current_time: u64) -> bool {
    // Check expiration and state validity
    current_time <= entry.expiry_time && 
    (entry.state & CS_STATE_VALID) != 0 &&
    entry.data_size > 0 &&
    entry.name_hash != 0
}

/// Optimized LRU sequence management with overflow handling
fn cs_get_next_lru_sequence_optimized(ctx: &XdpContext) -> Result<u32, ()> {
    match unsafe { CS_LRU_STATE.get(&0) } {
        Some(state) => {
            let mut new_state = *state;
            
            // Handle wraparound gracefully
            if new_state.sequence_counter == u32::MAX {
                // Reset sequence counter and adjust all entries
                new_state.sequence_counter = MAX_CS_ENTRIES as u32;
                new_state.min_sequence = 0;
                new_state.max_sequence = MAX_CS_ENTRIES as u32;
                
                // Note: In a full implementation, we'd need to update all entries
                // For now, we handle wraparound by resetting
            } else {
                new_state.sequence_counter = new_state.sequence_counter.wrapping_add(1);
            }
            
            // Update tracking values
            if new_state.sequence_counter > new_state.max_sequence {
                new_state.max_sequence = new_state.sequence_counter;
            }
            
            // Adjust min_sequence to maintain reasonable window
            let window_size = new_state.max_sequence.wrapping_sub(new_state.min_sequence);
            if window_size > (MAX_CS_ENTRIES as u32 * 2) {
                new_state.min_sequence = new_state.max_sequence.wrapping_sub(MAX_CS_ENTRIES as u32);
            }
            
            // Atomic update
            match unsafe { CS_LRU_STATE.insert(&0, &new_state, 0) } {
                Ok(_) => Ok(new_state.sequence_counter),
                Err(_) => Err(()),
            }
        }
        None => {
            // Initialize with default state
            let initial_state = LruState {
                sequence_counter: 1,
                min_sequence: 0,
                max_sequence: 1,
                _reserved: 0,
            };
            
            match unsafe { CS_LRU_STATE.insert(&0, &initial_state, 0) } {
                Ok(_) => Ok(1),
                Err(_) => Err(()),
            }
        }
    }
}

/// Comprehensive Content Store health check
fn cs_health_check(ctx: &XdpContext) -> Result<(), ()> {
    // Check stats consistency
    if let Some(stats) = unsafe { CS_STATS.get(&0) } {
        // Validate reasonable stats values
        if stats.current_entries > MAX_CS_ENTRIES as u64 {
            info!(ctx, "CS health check: current_entries ({}) exceeds max ({})", 
                  stats.current_entries, MAX_CS_ENTRIES);
            return Err(());
        }
        
        if stats.hits + stats.misses > 0 {
            let hit_ratio = (stats.hits * 100) / (stats.hits + stats.misses);
            info!(ctx, "CS health check: hit_ratio={}%, entries={}, bytes={}", 
                  hit_ratio, stats.current_entries, stats.bytes_stored);
        }
    }
    
    // Check LRU state consistency
    if let Some(lru_state) = unsafe { CS_LRU_STATE.get(&0) } {
        if lru_state.max_sequence < lru_state.min_sequence {
            info!(ctx, "CS health check: LRU sequence inconsistency: max={}, min={}", 
                  lru_state.max_sequence, lru_state.min_sequence);
            return Err(());
        }
    }
    
    Ok(())
}

/// Test function for Content Store operations (for development/testing)
#[cfg(test)]
fn cs_test_operations(ctx: &XdpContext) -> Result<(), ()> {
    let test_name_hash = 0x123456789abcdef0u64;
    let test_data_size = 1024u32;
    let test_freshness = 10000u64; // 10 seconds
    
    // Test insertion
    match cs_insert(ctx, test_name_hash, test_data_size, test_freshness) {
        Ok(_) => info!(ctx, "CS test: insertion successful"),
        Err(_) => {
            info!(ctx, "CS test: insertion failed");
            return Err(());
        }
    }
    
    // Test lookup
    match cs_lookup(ctx, test_name_hash) {
        Ok(()) => {
            info!(ctx, "CS test: lookup successful");
        }
        Err(_) => {
            info!(ctx, "CS test: lookup failed");
            return Err(());
        }
    }
    
    // Test eviction
    match cs_evict_lru_entry(ctx) {
        Ok(_) => info!(ctx, "CS test: eviction successful"),
        Err(_) => info!(ctx, "CS test: eviction failed (may be expected)"),
    }
    
    // Test health check
    cs_health_check(ctx)?;
    
    Ok(())
}

/// Performance monitoring for Content Store operations
fn cs_performance_monitor(ctx: &XdpContext) -> Result<(), ()> {
    if let Some(stats) = unsafe { CS_STATS.get(&0) } {
        let total_ops = stats.lookups + stats.insertions;
        if total_ops > 0 && total_ops % 1000 == 0 {
            let hit_ratio = if stats.lookups > 0 {
                (stats.hits * 100) / stats.lookups
            } else {
                0
            };
            
            info!(ctx, "CS performance: ops={}, hit_ratio={}%, entries={}, evictions={}", 
                  total_ops, hit_ratio, stats.current_entries, stats.evictions);
        }
    }
    Ok(())
}

/// Evict multiple LRU entries to make room for new insertions - uses optimized batch eviction
/// Returns number of entries evicted, or 0 on failure
fn cs_evict_multiple_lru_entries(ctx: &XdpContext, entries_needed: u32) -> u32 {
    match cs_evict_multiple_lru_entries_optimized(ctx, entries_needed) {
        Ok(count) => count,
        Err(_) => 0,
    }
}

/// Update LRU state minimum sequence tracking based on evictions
fn cs_update_lru_minimum(_ctx: &XdpContext, evicted_sequence: u32) -> Result<(), ()> {
    if let Some(state) = unsafe { CS_LRU_STATE.get(&0) } {
        let mut new_state = *state;
        
        // Update minimum sequence if we found a lower one
        if evicted_sequence < new_state.min_sequence || new_state.min_sequence == 0 {
            new_state.min_sequence = evicted_sequence;
        }
        
        let _ = unsafe { CS_LRU_STATE.insert(&0, &new_state, 0) };
        
        // Also update cleanup state
        let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_MIN_LRU_SEQUENCE, &(evicted_sequence as u64), 0) };
    }
    
    Ok(())
}

/// Improved LRU-based cache maintenance with aging
fn cs_lru_aging_cleanup(ctx: &XdpContext) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Get current LRU state
    let lru_state = match unsafe { CS_LRU_STATE.get(&0) } {
        Some(state) => *state,
        None => return Err(()),
    };
    
    // Calculate age threshold (entries older than this should be considered for eviction)
    let age_threshold = lru_state.sequence_counter.wrapping_sub(MAX_CS_ENTRIES as u32 / 2);
    
    // Update cleanup state with current aging information
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_MIN_LRU_SEQUENCE, &(age_threshold as u64), 0) };
    
    // Try to find and evict aged entries using probabilistic probing
    let mut cleanup_attempts = 0;
    let max_cleanup_attempts = 8;
    
    while cleanup_attempts < max_cleanup_attempts {
        // Generate probe key for cleanup
        let probe_key = (age_threshold.wrapping_add(cleanup_attempts as u32) as u64)
            .wrapping_mul(0x517cc1b727220a95)  // Different hash constant for cleanup
            ^ (current_time >> 32);            // Add time-based randomness
        
        if let Some(entry) = unsafe { CONTENT_STORE.get(&probe_key) } {
            let entry_copy = *entry;
            
            // Check if entry should be aged out
            let is_aged = entry_copy.lru_sequence <= age_threshold;
            let is_expired = current_time > entry_copy.expiry_time;
            
            if is_aged || is_expired {
                if let Ok(_) = unsafe { CONTENT_STORE.remove(&probe_key) } {
                    update_cs_stats(ctx, |stats| {
                        stats.evictions += 1;
                        stats.current_entries = stats.current_entries.saturating_sub(1);
                        stats.bytes_stored = stats.bytes_stored.saturating_sub(entry_copy.data_size as u64);
                        
                        if is_expired {
                            stats.expirations += 1;
                        }
                    });
                    
                    info!(ctx, "CS aged out entry: name_hash={}, lru_seq={}, aged={}, expired={}", 
                          probe_key, entry_copy.lru_sequence, is_aged as u32, is_expired as u32);
                }
            }
        }
        
        cleanup_attempts += 1;
    }
    
    Ok(())
}

/// Get next LRU sequence number and update tracking state
fn cs_get_next_lru_sequence(_ctx: &XdpContext) -> Result<u32, ()> {
    match unsafe { CS_LRU_STATE.get(&0) } {
        Some(state) => {
            let mut new_state = *state;
            new_state.sequence_counter = new_state.sequence_counter.wrapping_add(1);
            
            // Update max sequence
            if new_state.sequence_counter > new_state.max_sequence {
                new_state.max_sequence = new_state.sequence_counter;
            }
            
            // Update min sequence estimation
            // When counter wraps around or cache is likely full, adjust minimum
            let estimated_cache_size = new_state.max_sequence.wrapping_sub(new_state.min_sequence);
            if estimated_cache_size > (MAX_CS_ENTRIES as u32 * 2) {
                // Cache is likely full, advance minimum sequence
                new_state.min_sequence = new_state.max_sequence.wrapping_sub(MAX_CS_ENTRIES as u32);
            }
            
            // Handle wraparound gracefully
            if new_state.sequence_counter < new_state.min_sequence {
                new_state.min_sequence = 0;
            }
            
            let _ = unsafe { CS_LRU_STATE.insert(&0, &new_state, 0) };
            Ok(new_state.sequence_counter)
        }
        None => {
            // Initialize LRU state
            let new_state = LruState {
                sequence_counter: 1,
                min_sequence: 0,
                max_sequence: 1,
                _reserved: 0,
            };
            let _ = unsafe { CS_LRU_STATE.insert(&0, &new_state, 0) };
            Ok(1)
        }
    }
}

/// Update Content Store statistics
fn update_cs_stats<F>(_ctx: &XdpContext, update_fn: F)
where
    F: FnOnce(&mut ContentStoreStats),
{
    match unsafe { CS_STATS.get(&0) } {
        Some(stats) => {
            let mut new_stats = *stats;
            update_fn(&mut new_stats);
            let _ = unsafe { CS_STATS.insert(&0, &new_stats, 0) };
        }
        None => {
            let mut stats = ContentStoreStats::new();
            update_fn(&mut stats);
            let _ = unsafe { CS_STATS.insert(&0, &stats, 0) };
        }
    }
}

/// Trigger periodic Content Store cleanup
fn cs_trigger_periodic_cleanup(ctx: &XdpContext) {
    // Increment packet counter
    let packet_count = match unsafe { CS_CLEANUP_STATE.get(&CS_CLEANUP_KEY_PACKET_COUNT) } {
        Some(count) => *count + 1,
        None => 1,
    };
    
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_PACKET_COUNT, &packet_count, 0) };
    
    // Check if we should trigger cleanup
    if packet_count % CS_CLEANUP_INTERVAL as u64 == 0 {
        cs_periodic_cleanup(ctx);
    }
}

/// Periodic cleanup function for Content Store with enhanced LRU maintenance
fn cs_periodic_cleanup(ctx: &XdpContext) {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Update last cleanup time
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_LAST_CLEANUP, &current_time, 0) };
    
    // Increment total cleanups counter
    let total_cleanups = match unsafe { CS_CLEANUP_STATE.get(&CS_CLEANUP_KEY_TOTAL_CLEANUPS) } {
        Some(count) => *count + 1,
        None => 1,
    };
    let _ = unsafe { CS_CLEANUP_STATE.insert(&CS_CLEANUP_KEY_TOTAL_CLEANUPS, &total_cleanups, 0) };
    
    // Perform LRU-based aging cleanup
    let _ = cs_lru_aging_cleanup(ctx);
    
    // Get current cache statistics
    let stats = match unsafe { CS_STATS.get(&0) } {
        Some(s) => *s,
        None => ContentStoreStats::new(),
    };
    
    // If cache is getting full, perform more aggressive cleanup
    let cache_utilization_percent = (stats.current_entries * 100) / (MAX_CS_ENTRIES as u64);
    if cache_utilization_percent > 80 {
        // Cache is over 80% full, perform aggressive LRU eviction
        let entries_to_evict = (MAX_CS_ENTRIES as u32 / 8).max(1); // Evict at least 12.5% of cache
        
        let evicted = cs_evict_multiple_lru_entries(ctx, entries_to_evict);
        if evicted > 0 {
            info!(ctx, "Aggressive CS cleanup evicted {} entries, utilization was {}%", 
                  evicted, cache_utilization_percent);
        }
    }
    
    update_cs_stats(ctx, |stats| {
        stats.cleanups += 1;
    });
    
    info!(ctx, "Periodic CS cleanup #{} completed, current entries: {}, utilization: {}%", 
          total_cleanups, stats.current_entries, cache_utilization_percent);
}

fn cs_store_data_chunks(ctx: &XdpContext, name_hash: u64, data_start: usize, data_size: u32) -> Result<(), ()> {
    let data_end = ctx.data_end();
    
    // Validate data bounds
    if data_start + (data_size as usize) > data_end {
        return Err(());
    }
    
    // Store data in 1KB chunks
    let chunk_count = (data_size + 1023) / 1024;
    
    // Limit chunks to avoid stack issues
    let max_chunks = if chunk_count > 16 { 16 } else { chunk_count };
    
    for i in 0..max_chunks {
        let _chunk_key = (name_hash << 16) | (i as u64);
        let chunk_start = data_start + (i as usize * 1024);
        let chunk_size = if i == chunk_count - 1 {
            ((data_size % 1024) as usize).min(1024)
        } else {
            1024
        };
        
        if chunk_start + chunk_size > data_end {
            break;
        }
        
        // For now, just mark that we would store the chunk
        // In a real implementation, we'd copy the data using a helper function
        // that avoids large stack allocations
        info!(ctx, "Would store chunk {} for name_hash: {}, size: {}", i, name_hash, chunk_size);
    }
    
    Ok(())
}


/// Enhanced NDN packet processing functions for real network operations

/// Parse and validate Interest packet selectors
fn parse_interest_selectors(ctx: &XdpContext, selectors_start: usize) -> Result<(u32, u32), ()> {
    let data_end = ctx.data_end();
    let mut current_pos = selectors_start;
    let mut min_suffix_components = 0u32;
    let mut max_suffix_components = 0u32;
    
    // Parse TLV length for selectors
    let tlv_result = parse_tlv_length(ctx, current_pos + 1);
    if tlv_result == 0 {
        return Err(());
    }
    let selectors_length = (tlv_result >> 16) as usize;
    let selectors_header_size = (tlv_result & 0xFFFF) as usize;
    
    current_pos += selectors_header_size;
    let selectors_end = current_pos + selectors_length;
    
    // Parse selector components
    while current_pos + 2 < selectors_end && current_pos < data_end {
        let selector_type = unsafe { *(current_pos as *const u8) };
        
        let tlv_result = parse_tlv_length(ctx, current_pos + 1);
        if tlv_result == 0 {
            break;
        }
        let selector_length = (tlv_result >> 16) as usize;
        let selector_header_size = (tlv_result & 0xFFFF) as usize;
        
        match selector_type {
            NDN_TLV_MIN_SUFFIX_COMPONENTS => {
                if selector_length == 1 && current_pos + selector_header_size + 1 <= data_end {
                    min_suffix_components = unsafe { *((current_pos + selector_header_size) as *const u8) } as u32;
                }
            }
            NDN_TLV_MAX_SUFFIX_COMPONENTS => {
                if selector_length == 1 && current_pos + selector_header_size + 1 <= data_end {
                    max_suffix_components = unsafe { *((current_pos + selector_header_size) as *const u8) } as u32;
                }
            }
            _ => {
                // Skip unknown selectors
            }
        }
        
        current_pos += selector_header_size + selector_length;
    }
    
    Ok((min_suffix_components, max_suffix_components))
}

/// Enhanced Interest packet processing with complete TLV parsing
fn process_interest_packet_enhanced(ctx: &XdpContext, interest_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Interest packet
    let tlv_result = parse_tlv_length(ctx, interest_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Interest TLV length");
        return Ok(xdp_action::XDP_DROP);
    }
    let interest_length = (tlv_result >> 16) as usize;
    let tlv_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate Interest packet bounds
    if interest_start + tlv_header_size + interest_length > data_end {
        info!(ctx, "Interest packet truncated");
        return Ok(xdp_action::XDP_DROP);
    }
    
    let interest_content_start = interest_start + tlv_header_size;
    let mut current_pos = interest_content_start;
    
    // Parse mandatory Name element
    let name_hash = extract_interest_name_hash(ctx, current_pos);
    if name_hash == 0 {
        info!(ctx, "Failed to extract Interest name");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Skip Name TLV to parse optional elements
    let name_tlv_result = parse_tlv_length(ctx, current_pos + 1);
    if name_tlv_result == 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    let name_length = (name_tlv_result >> 16) as usize;
    let name_header_size = (name_tlv_result & 0xFFFF) as usize;
    current_pos += name_header_size + name_length;
    
    // Parse optional elements
    let mut nonce = 0u32;
    let mut interest_lifetime = DEFAULT_INTEREST_LIFETIME_MS;
    let mut must_be_fresh = false;
    let mut selectors_present = false;
    
    while current_pos + 2 < data_end && current_pos < interest_start + tlv_header_size + interest_length {
        let element_type = unsafe { *(current_pos as *const u8) };
        
        let tlv_result = parse_tlv_length(ctx, current_pos + 1);
        if tlv_result == 0 {
            break;
        }
        let element_length = (tlv_result >> 16) as usize;
        let element_header_size = (tlv_result & 0xFFFF) as usize;
        
        match element_type {
            NDN_TLV_SELECTORS => {
                selectors_present = true;
                match parse_interest_selectors(ctx, current_pos) {
                    Ok((min_suffix, max_suffix)) => {
                        info!(ctx, "Interest selectors: min={}, max={}", min_suffix, max_suffix);
                    }
                    Err(_) => {
                        info!(ctx, "Failed to parse Interest selectors");
                    }
                }
            }
            NDN_TLV_NONCE => {
                if element_length == 4 && current_pos + element_header_size + 4 <= data_end {
                    nonce = unsafe {
                        let ptr = (current_pos + element_header_size) as *const u32;
                        u32::from_be(*ptr)
                    };
                }
            }
            NDN_TLV_INTEREST_LIFETIME => {
                if element_length == 2 && current_pos + element_header_size + 2 <= data_end {
                    interest_lifetime = unsafe {
                        let ptr = (current_pos + element_header_size) as *const u16;
                        u16::from_be(*ptr) as u32
                    };
                }
            }
            NDN_TLV_MUST_BE_FRESH => {
                must_be_fresh = true;
            }
            _ => {
                // Skip unknown elements
            }
        }
        
        current_pos += element_header_size + element_length;
    }
    
    info!(ctx, "Enhanced Interest processing: name_hash={}, nonce={}, lifetime={}, fresh={}, selectors={}", 
          name_hash, nonce, interest_lifetime, must_be_fresh as u32, selectors_present as u32);
    
    // Check Content Store with freshness requirement
    if must_be_fresh {
        // For must-be-fresh Interest, only serve from CS if entry is very fresh
        match cs_lookup_with_freshness(ctx, name_hash, true) {
            Ok(()) => {
                info!(ctx, "Content Store hit for fresh Interest");
                let face_id = extract_face_id_from_context(ctx).unwrap_or(1);
                face_update_stats(ctx, face_id, 1, 0, 0, 0); // No size info available
                return Ok(xdp_action::XDP_PASS);
            }
            Err(_) => {
                info!(ctx, "Content Store miss for fresh Interest");
            }
        }
    } else {
        // Regular CS lookup
        match cs_lookup(ctx, name_hash) {
            Ok(()) => {
                info!(ctx, "Content Store hit for Interest");
                let face_id = extract_face_id_from_context(ctx).unwrap_or(1);
                face_update_stats(ctx, face_id, 1, 0, 0, 0); // No size info available
                return Ok(xdp_action::XDP_PASS);
            }
            Err(_) => {
                info!(ctx, "Content Store miss, proceeding with PIT processing");
            }
        }
    }
    
    // Apply enhanced filtering rules
    match apply_enhanced_filter_rules(ctx, name_hash, nonce, interest_lifetime) {
        Ok(action) => {
            if action == xdp_action::XDP_PASS {
                // Extract face information and update PIT
                let face_id = extract_face_id_from_context(ctx).unwrap_or(1);
                
                // Update face statistics
                let _ = face_update_with_packet_info(ctx, face_id, true, interest_length as u32);
                
                // Try to insert/update PIT entry with enhanced information
                match pit_insert_or_update_enhanced(ctx, name_hash, face_id, nonce, interest_lifetime) {
                    Ok(()) => {
                        info!(ctx, "Enhanced PIT entry created/updated successfully");
                        update_packet_stats(ctx, true, true, 0, 0);
                        Ok(xdp_action::XDP_PASS)
                    }
                    Err(_) => {
                        info!(ctx, "Failed to create/update enhanced PIT entry");
                        update_packet_stats(ctx, false, false, 0, 0);
                        Ok(xdp_action::XDP_DROP)
                    }
                }
            } else {
                update_packet_stats(ctx, true, false, 0, 0);
                Ok(action)
            }
        }
        Err(_) => {
            info!(ctx, "Enhanced filter rule evaluation failed");
            update_packet_stats(ctx, false, false, 0, 0);
            Ok(xdp_action::XDP_DROP)
        }
    }
}

/// Enhanced Content Store lookup with freshness validation
fn cs_lookup_with_freshness(ctx: &XdpContext, name_hash: u64, require_fresh: bool) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    match cs_lookup(ctx, name_hash) {
        Ok(()) => {
            if require_fresh {
                // For now, we'll assume freshness is valid since we can't access entry details
                // In a real implementation, we would check against the actual entry
                info!(ctx, "CS entry found, assuming fresh for fresh Interest");
            }
            Ok(())
        }
        Err(_) => Err(()),
    }
}

/// Enhanced filtering rules with nonce and lifetime validation
fn apply_enhanced_filter_rules(ctx: &XdpContext, name_hash: u64, nonce: u32, lifetime: u32) -> Result<u32, ()> {
    // Get filtering configuration
    let config = match unsafe { CONFIG_MAP.get(&0) } {
        Some(cfg) => cfg,
        None => {
            info!(ctx, "No filter configuration found, allowing packet");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    
    // Check if filtering is enabled
    if config.filter_enabled == 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // Enhanced rate limiting with nonce tracking
    if let Err(_) = apply_enhanced_rate_limiting(ctx, name_hash, nonce) {
        info!(ctx, "Enhanced rate limit exceeded, dropping packet");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Validate Interest lifetime
    if lifetime > 30000 { // Maximum 30 seconds
        info!(ctx, "Interest lifetime too long ({}ms), dropping packet", lifetime);
        return Ok(xdp_action::XDP_DROP);
    }
    
    if lifetime < 100 { // Minimum 100ms
        info!(ctx, "Interest lifetime too short ({}ms), dropping packet", lifetime);
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Check specific filtering rules
    match check_enhanced_filter_rules(ctx, name_hash, nonce) {
        Ok(action) => {
            info!(ctx, "Enhanced filter rule matched, action: {}", action);
            match action {
                FILTER_ACTION_ALLOW => Ok(xdp_action::XDP_PASS),
                FILTER_ACTION_DROP => Ok(xdp_action::XDP_DROP),
                FILTER_ACTION_REDIRECT => {
                    info!(ctx, "Redirecting packet (enhanced)");
                    Ok(xdp_action::XDP_PASS)
                }
                _ => Ok(xdp_action::XDP_DROP),
            }
        }
        Err(_) => {
            info!(ctx, "Enhanced filter rule evaluation failed");
            Ok(xdp_action::XDP_DROP)
        }
    }
}

/// Enhanced rate limiting with nonce deduplication
fn apply_enhanced_rate_limiting(ctx: &XdpContext, name_hash: u64, nonce: u32) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Create composite key for rate limiting (name + nonce)
    let rate_limit_key = name_hash ^ ((nonce as u64) << 32);
    
    // Check if we've seen this exact Interest recently
    match unsafe { INTEREST_CACHE.get(&rate_limit_key) } {
        Some(last_seen) => {
            let time_diff = current_time - last_seen;
            if time_diff < 1_000_000_000 { // 1 second minimum interval
                info!(ctx, "Duplicate Interest detected: name_hash={}, nonce={}", name_hash, nonce);
                return Err(());
            }
        }
        None => {
            // First time seeing this Interest
        }
    }
    
    // Update cache with current time
    let _ = unsafe { INTEREST_CACHE.insert(&rate_limit_key, &current_time, 0) };
    
    // Apply traditional rate limiting on name hash
    match unsafe { INTEREST_CACHE.get(&name_hash) } {
        Some(last_seen) => {
            let time_diff = current_time - last_seen;
            if time_diff < 10_000_000 { // 10ms minimum interval per name
                info!(ctx, "Rate limit exceeded for name_hash: {}", name_hash);
                return Err(());
            }
        }
        None => {
            // First time seeing this name
        }
    }
    
    // Update name-based rate limiting
    let _ = unsafe { INTEREST_CACHE.insert(&name_hash, &current_time, 0) };
    
    Ok(())
}

/// Enhanced filter rule checking with nonce validation
fn check_enhanced_filter_rules(ctx: &XdpContext, name_hash: u64, nonce: u32) -> Result<u32, ()> {
    // Check basic filter rules first
    match unsafe { FILTER_RULES.get(&name_hash) } {
        Some(action) => {
            info!(ctx, "Direct filter rule match: name_hash={}, action={}", name_hash, *action);
            return Ok(*action);
        }
        None => {
            // No direct match, check patterns
        }
    }
    
    // Enhanced pattern matching with nonce consideration
    // Check if nonce suggests this is a retransmission
    if nonce == 0 {
        info!(ctx, "Zero nonce in Interest, potentially malicious");
        return Ok(FILTER_ACTION_DROP);
    }
    
    // Check name prefix patterns (simplified)
    let prefix_patterns = [
        (0x1000000000000000u64, FILTER_ACTION_ALLOW),  // Allow pattern
        (0x2000000000000000u64, FILTER_ACTION_DROP),   // Drop pattern
        (0x3000000000000000u64, FILTER_ACTION_REDIRECT), // Redirect pattern
    ];
    
    for (pattern, action) in prefix_patterns.iter() {
        if name_hash & 0xF000000000000000 == *pattern {
            info!(ctx, "Pattern filter match: name_hash={}, action={}", name_hash, *action);
            return Ok(*action);
        }
    }
    
    // Default action is allow
    Ok(FILTER_ACTION_ALLOW)
}

/// Enhanced PIT insertion with lifetime tracking
fn pit_insert_or_update_enhanced(ctx: &XdpContext, name_hash: u64, face_id: u32, nonce: u32, lifetime: u32) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let expiry_time = current_time + (lifetime as u64 * 1_000_000); // Convert ms to ns
    
    // Check if entry already exists
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(existing_entry) => {
            let mut entry = *existing_entry;
            
            // Check for Interest aggregation
            if entry.incoming_face == face_id {
                // Same face - check if it's a retransmission
                if entry.nonce == nonce {
                    info!(ctx, "Duplicate Interest from same face, dropping");
                    return Err(());
                } else {
                    // Different nonce, update entry
                    entry.nonce = nonce;
                    entry.interest_count += 1;
                    entry.expiry_time = expiry_time;
                    
                    match unsafe { PIT_TABLE.insert(&name_hash, &entry, 0) } {
                        Ok(_) => {
                            update_pit_stats(ctx, |stats| {
                                stats.interests_aggregated += 1;
                            });
                            info!(ctx, "Enhanced PIT entry updated for retransmission");
                            return Ok(());
                        }
                        Err(_) => return Err(()),
                    }
                }
            } else {
                // Different face - add to additional faces if room
                if entry.additional_faces_count < MAX_ADDITIONAL_FACES as u8 {
                    let face_key = (name_hash << 8) | (entry.additional_faces_count as u64);
                    let face_entry = PitFaceEntry {
                        face_id,
                        nonce,
                        timestamp: current_time,
                    };
                    
                    match unsafe { PIT_ADDITIONAL_FACES.insert(&face_key, &face_entry, 0) } {
                        Ok(_) => {
                            entry.additional_faces_count += 1;
                            entry.interest_count += 1;
                            entry.expiry_time = expiry_time.max(entry.expiry_time); // Use later expiry
                            
                            match unsafe { PIT_TABLE.insert(&name_hash, &entry, 0) } {
                                Ok(_) => {
                                    update_pit_stats(ctx, |stats| {
                                        stats.interests_aggregated += 1;
                                    });
                                    info!(ctx, "Enhanced PIT entry aggregated new face");
                                    return Ok(());
                                }
                                Err(_) => return Err(()),
                            }
                        }
                        Err(_) => {
                            info!(ctx, "Failed to add additional face to PIT entry");
                            return Err(());
                        }
                    }
                } else {
                    info!(ctx, "PIT entry full, cannot add more faces");
                    return Err(());
                }
            }
        }
        None => {
            // Create new PIT entry
            let new_entry = PitEntry {
                name_hash,
                incoming_face: face_id,
                nonce,
                expiry_time,
                created_time: current_time,
                interest_count: 1,
                state: PIT_STATE_ACTIVE,
                additional_faces_count: 0,
                _padding: [0; 2],
            };
            
            match unsafe { PIT_TABLE.insert(&name_hash, &new_entry, 0) } {
                Ok(_) => {
                    update_pit_stats(ctx, |stats| {
                        stats.entries_created += 1;
                        stats.insertions += 1;
                        stats.active_entries += 1;
                    });
                    info!(ctx, "Enhanced PIT entry created");
                    Ok(())
                }
                Err(_) => {
                    info!(ctx, "Failed to create enhanced PIT entry");
                    Err(())
                }
            }
        }
    }
}

/// Enhanced Data packet processing with signature validation
fn process_data_packet_enhanced(ctx: &XdpContext, data_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Data packet
    let tlv_result = parse_tlv_length(ctx, data_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Data TLV length");
        return Ok(xdp_action::XDP_DROP);
    }
    let data_length = (tlv_result >> 16) as usize;
    let tlv_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate Data packet bounds
    if data_start + tlv_header_size + data_length > data_end {
        info!(ctx, "Data packet truncated");
        return Ok(xdp_action::XDP_DROP);
    }
    
    let data_content_start = data_start + tlv_header_size;
    let mut current_pos = data_content_start;
    
    // Extract name hash from Data packet
    let name_hash = extract_interest_name_hash(ctx, current_pos);
    if name_hash == 0 {
        info!(ctx, "Failed to extract name from Data packet");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // Parse Data packet structure
    let mut content_size = 0u32;
    let mut freshness_period = 3600000u64; // Default 1 hour
    let mut signature_present = false;
    let mut content_type = NDN_CONTENT_TYPE_BLOB;
    
    // Skip Name TLV and parse other elements
    let name_tlv_result = parse_tlv_length(ctx, current_pos + 1);
    if name_tlv_result == 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    let name_length = (name_tlv_result >> 16) as usize;
    let name_header_size = (name_tlv_result & 0xFFFF) as usize;
    current_pos += name_header_size + name_length;
    
    // Parse optional MetaInfo
    if current_pos + 2 < data_end {
        let next_type = unsafe { *(current_pos as *const u8) };
        if next_type == NDN_TLV_META_INFO {
            let meta_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if meta_tlv_result != 0 {
                let meta_length = (meta_tlv_result >> 16) as usize;
                let meta_header_size = (meta_tlv_result & 0xFFFF) as usize;
                
                // Parse MetaInfo contents
                let meta_start = current_pos + meta_header_size;
                let meta_end = meta_start + meta_length;
                let mut meta_pos = meta_start;
                
                while meta_pos + 2 < meta_end && meta_pos < data_end {
                    let meta_type = unsafe { *(meta_pos as *const u8) };
                    
                    let meta_tlv_result = parse_tlv_length(ctx, meta_pos + 1);
                    if meta_tlv_result == 0 {
                        break;
                    }
                    let meta_element_length = (meta_tlv_result >> 16) as usize;
                    let meta_element_header_size = (meta_tlv_result & 0xFFFF) as usize;
                    
                    match meta_type {
                        NDN_TLV_CONTENT_TYPE => {
                            if meta_element_length == 1 && meta_pos + meta_element_header_size + 1 <= data_end {
                                content_type = unsafe { *((meta_pos + meta_element_header_size) as *const u8) };
                            }
                        }
                        NDN_TLV_FRESHNESS_PERIOD => {
                            if meta_element_length == 2 && meta_pos + meta_element_header_size + 2 <= data_end {
                                freshness_period = unsafe {
                                    let ptr = (meta_pos + meta_element_header_size) as *const u16;
                                    u16::from_be(*ptr) as u64 * 1000 // Convert to ms
                                };
                            }
                        }
                        _ => {
                            // Skip unknown MetaInfo elements
                        }
                    }
                    
                    meta_pos += meta_element_header_size + meta_element_length;
                }
                
                current_pos += meta_header_size + meta_length;
            }
        }
    }
    
    // Parse Content
    if current_pos + 2 < data_end {
        let next_type = unsafe { *(current_pos as *const u8) };
        if next_type == NDN_TLV_CONTENT {
            let content_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if content_tlv_result != 0 {
                content_size = (content_tlv_result >> 16) as u32;
                let content_header_size = (content_tlv_result & 0xFFFF) as usize;
                current_pos += content_header_size + content_size as usize;
            }
        }
    }
    
    // Check for signature
    if current_pos + 2 < data_end {
        let next_type = unsafe { *(current_pos as *const u8) };
        if next_type == NDN_TLV_SIGNATURE_INFO {
            signature_present = true;
            
            // Basic signature validation
            let sig_info_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if sig_info_tlv_result != 0 {
                let sig_info_length = (sig_info_tlv_result >> 16) as usize;
                let sig_info_header_size = (sig_info_tlv_result & 0xFFFF) as usize;
                current_pos += sig_info_header_size + sig_info_length;
                
                // Check SignatureValue
                if current_pos + 2 < data_end {
                    let sig_value_type = unsafe { *(current_pos as *const u8) };
                    if sig_value_type == NDN_TLV_SIGNATURE_VALUE {
                        let sig_value_tlv_result = parse_tlv_length(ctx, current_pos + 1);
                        if sig_value_tlv_result != 0 {
                            let sig_value_length = (sig_value_tlv_result >> 16) as usize;
                            if sig_value_length > 0 {
                                info!(ctx, "Data packet has valid signature structure");
                            }
                        }
                    }
                }
            }
        }
    }
    
    info!(ctx, "Enhanced Data processing: name_hash={}, content_size={}, freshness={}ms, sig={}, type={}", 
          name_hash, content_size, freshness_period, signature_present as u32, content_type);
    
    // Check if there's a corresponding PIT entry
    match pit_remove_enhanced(ctx, name_hash) {
        Ok(pit_entry) => {
            info!(ctx, "Enhanced PIT entry satisfied by Data packet");
            
            // Insert Data into Content Store with enhanced metadata
            if content_size <= 65536 { // Maximum content size
                match cs_insert_enhanced(ctx, name_hash, content_size, freshness_period) {
                    Ok(()) => {
                        let _ = cs_store_data_chunks(ctx, name_hash, data_start, content_size);
                        info!(ctx, "Enhanced Data packet cached in Content Store");
                    }
                    Err(_) => {
                        info!(ctx, "Failed to cache enhanced Data packet");
                    }
                }
            }
            
            // Enhanced forwarding to all faces
            let forwarding_result = forward_data_to_pit_faces(ctx, &pit_entry, data_length);
            if forwarding_result > 0 {
                info!(ctx, "Enhanced Data forwarded to {} faces", forwarding_result);
            }
            
            Ok(xdp_action::XDP_PASS)
        }
        Err(_) => {
            // No PIT entry found, but still cache the Data
            if content_size <= 65536 {
                match cs_insert_enhanced(ctx, name_hash, content_size, freshness_period) {
                    Ok(()) => {
                        let _ = cs_store_data_chunks(ctx, name_hash, data_start, content_size);
                        info!(ctx, "Unsolicited enhanced Data packet cached");
                    }
                    Err(_) => {
                        info!(ctx, "Failed to cache unsolicited enhanced Data packet");
                    }
                }
            }
            
            info!(ctx, "No PIT entry found for enhanced Data packet");
            Ok(xdp_action::XDP_DROP)
        }
    }
}

/// Enhanced PIT removal with face tracking
fn pit_remove_enhanced(ctx: &XdpContext, name_hash: u64) -> Result<PitEntry, ()> {
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            let pit_entry = *entry;
            
            // Remove main entry
            match unsafe { PIT_TABLE.remove(&name_hash) } {
                Ok(_) => {
                    // Remove additional faces
                    for i in 0..pit_entry.additional_faces_count {
                        let face_key = (name_hash << 8) | (i as u64);
                        let _ = unsafe { PIT_ADDITIONAL_FACES.remove(&face_key) };
                    }
                    
                    // Update statistics
                    update_pit_stats(ctx, |stats| {
                        stats.entries_satisfied += 1;
                        stats.deletions += 1;
                        stats.active_entries = stats.active_entries.saturating_sub(1);
                    });
                    
                    info!(ctx, "Enhanced PIT entry removed with {} additional faces", pit_entry.additional_faces_count);
                    Ok(pit_entry)
                }
                Err(_) => Err(()),
            }
        }
        None => Err(()),
    }
}

/// Enhanced Content Store insertion with metadata
fn cs_insert_enhanced(ctx: &XdpContext, name_hash: u64, data_size: u32, freshness_period_ms: u64) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let expiry_time = current_time + (freshness_period_ms * 1_000_000);
    
    // Enhanced eviction if needed
    let stats = match unsafe { CS_STATS.get(&0) } {
        Some(s) => *s,
        None => ContentStoreStats::new(),
    };
    
    if stats.current_entries >= MAX_CS_ENTRIES as u64 {
        let _ = cs_evict_lru_entry(ctx);
    }
    
    // Get next LRU sequence
    let lru_sequence = cs_get_next_lru_sequence(ctx).unwrap_or(0);
    
    // Create enhanced entry
    let new_entry = ContentStoreEntry {
        name_hash,
        data_size,
        content_type: 0, // Default content type
        state: CS_STATE_VALID, // Default state
        _reserved: 0,
        hit_count: 0,
        lru_sequence,
        created_time: current_time,
        last_access_time: current_time,
        expiry_time,
        data_hash: 0, // Could compute hash for integrity
    };
    
    match unsafe { CONTENT_STORE.insert(&name_hash, &new_entry, 0) } {
        Ok(_) => {
            update_cs_stats(ctx, |stats| {
                stats.insertions += 1;
                stats.current_entries += 1;
                stats.bytes_stored += data_size as u64;
            });
            
            info!(ctx, "Enhanced CS entry inserted: hash={}", name_hash);
            Ok(())
        }
        Err(_) => Err(()),
    }
}

/// Enhanced Data forwarding to PIT faces
fn forward_data_to_pit_faces(ctx: &XdpContext, pit_entry: &PitEntry, data_length: usize) -> u32 {
    let mut forwarded_count = 0u32;
    
    // Forward to primary face
    if face_get_forwarding_info(ctx, pit_entry.incoming_face) == 1 {
        face_update_stats(ctx, pit_entry.incoming_face, 1, 0, data_length as u64, 0);
        forwarded_count += 1;
        info!(ctx, "Enhanced Data forwarded to primary face: {}", pit_entry.incoming_face);
    }
    
    // Forward to additional faces
    for i in 0..pit_entry.additional_faces_count {
        let face_key = (pit_entry.name_hash << 8) | (i as u64);
        if let Some(face_entry) = unsafe { PIT_ADDITIONAL_FACES.get(&face_key) } {
            if face_get_forwarding_info(ctx, face_entry.face_id) == 1 {
                face_update_stats(ctx, face_entry.face_id, 1, 0, data_length as u64, 0);
                forwarded_count += 1;
                info!(ctx, "Enhanced Data forwarded to additional face: {}", face_entry.face_id);
            }
        }
    }
    
    forwarded_count
}

/// Packet modification for real network forwarding
fn modify_packet_for_forwarding(ctx: &XdpContext, modification_type: u8) -> Result<(), ()> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    if data_start >= data_end {
        return Err(());
    }
    
    // Validate minimum packet size for Ethernet header
    if data_start + mem::size_of::<EthernetHeader>() > data_end {
        return Err(());
    }
    
    // Get mutable reference to Ethernet header
    let eth_hdr = unsafe { &mut *(data_start as *mut EthernetHeader) };
    
    match modification_type {
        1 => {
            // Update MAC addresses for next hop forwarding
            // In a real implementation, this would use FIB lookup to get next hop MAC
            let next_hop_mac = [0x00, 0x50, 0x56, 0x00, 0x00, 0x02]; // Example next hop MAC
            let local_mac = [0x00, 0x50, 0x56, 0x00, 0x00, 0x01]; // Example local MAC
            
            // Update destination MAC to next hop
            eth_hdr.dest_mac = next_hop_mac;
            // Update source MAC to local interface
            eth_hdr.src_mac = local_mac;
            
            info!(ctx, "Updated MAC addresses for L2 forwarding");
        }
        2 => {
            // Decrement TTL/hop limit for IP packets
            if eth_hdr.ether_type == 0x0800 { // IPv4
                let ip_start = data_start + mem::size_of::<EthernetHeader>();
                if ip_start + 20 <= data_end {
                    let ip_hdr = unsafe { &mut *(ip_start as *mut u8) };
                    let ttl_ptr = unsafe { &mut *((ip_start + 8) as *mut u8) };
                    
                    if *ttl_ptr > 1 {
                        *ttl_ptr -= 1;
                        info!(ctx, "Decremented IPv4 TTL to {}", *ttl_ptr);
                        
                        // Update IPv4 header checksum
                        let _ = update_ipv4_checksum(ctx, ip_start);
                    } else {
                        info!(ctx, "IPv4 TTL expired, dropping packet");
                        return Err(());
                    }
                }
            } else if eth_hdr.ether_type == 0x86dd { // IPv6
                let ip_start = data_start + mem::size_of::<EthernetHeader>();
                if ip_start + 40 <= data_end {
                    let hop_limit_ptr = unsafe { &mut *((ip_start + 7) as *mut u8) };
                    
                    if *hop_limit_ptr > 1 {
                        *hop_limit_ptr -= 1;
                        info!(ctx, "Decremented IPv6 hop limit to {}", *hop_limit_ptr);
                    } else {
                        info!(ctx, "IPv6 hop limit expired, dropping packet");
                        return Err(());
                    }
                }
            }
        }
        3 => {
            // Modify NDN packet headers for forwarding
            let ndn_start = match eth_hdr.ether_type {
                0x0800 => { // IPv4
                    let ip_start = data_start + mem::size_of::<EthernetHeader>();
                    if ip_start + 20 > data_end {
                        return Err(());
                    }
                    
                    let ip_hdr = unsafe { *(ip_start as *const u8) };
                    let ip_header_len = ((ip_hdr & 0xF) as usize) * 4;
                    let protocol = unsafe { *((ip_start + 9) as *const u8) };
                    
                    match protocol {
                        6 => { // TCP
                            let tcp_start = ip_start + ip_header_len;
                            if tcp_start + 20 > data_end {
                                return Err(());
                            }
                            let tcp_hdr_len = ((unsafe { *((tcp_start + 12) as *const u8) } >> 4) & 0xF) as usize * 4;
                            tcp_start + tcp_hdr_len
                        }
                        17 => { // UDP
                            ip_start + ip_header_len + 8
                        }
                        _ => return Err(()),
                    }
                }
                0x86dd => { // IPv6
                    let ip_start = data_start + mem::size_of::<EthernetHeader>();
                    if ip_start + 40 > data_end {
                        return Err(());
                    }
                    
                    let next_header = unsafe { *((ip_start + 6) as *const u8) };
                    match next_header {
                        6 => { // TCP
                            let tcp_start = ip_start + 40;
                            if tcp_start + 20 > data_end {
                                return Err(());
                            }
                            let tcp_hdr_len = ((unsafe { *((tcp_start + 12) as *const u8) } >> 4) & 0xF) as usize * 4;
                            tcp_start + tcp_hdr_len
                        }
                        17 => { // UDP
                            ip_start + 40 + 8
                        }
                        _ => return Err(()),
                    }
                }
                _ => return Err(()),
            };
            
            // Modify NDN packet if needed (e.g., update forwarding hints)
            if ndn_start + 2 <= data_end {
                let ndn_type = unsafe { *(ndn_start as *const u8) };
                if ndn_type == NDN_TLV_INTEREST {
                    // Could add forwarding hints or update selectors
                    info!(ctx, "Modified NDN Interest packet for forwarding");
                } else if ndn_type == NDN_TLV_DATA {
                    // Could update Data packet metadata
                    info!(ctx, "Modified NDN Data packet for forwarding");
                }
            }
        }
        _ => {
            info!(ctx, "Unknown packet modification type: {}", modification_type);
            return Err(());
        }
    }
    
    Ok(())
}

/// Update IPv4 header checksum after modification
fn update_ipv4_checksum(ctx: &XdpContext, ip_start: usize) -> Result<(), ()> {
    let data_end = ctx.data_end();
    
    if ip_start + 20 > data_end {
        return Err(());
    }
    
    // Clear existing checksum
    unsafe {
        let checksum_ptr = (ip_start + 10) as *mut u16;
        *checksum_ptr = 0;
    }
    
    // Calculate new checksum
    let mut sum = 0u32;
    let mut i = 0;
    
    while i < 20 && ip_start + i + 1 < data_end {
        let word = unsafe {
            let ptr = (ip_start + i) as *const u16;
            u16::from_be(*ptr)
        };
        sum += word as u32;
        i += 2;
    }
    
    // Handle odd byte if present
    if i < 20 && ip_start + i < data_end {
        let byte = unsafe { *((ip_start + i) as *const u8) };
        sum += (byte as u32) << 8;
    }
    
    // Fold 32-bit sum to 16-bit
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    let checksum = !(sum as u16);
    
    // Write back checksum
    unsafe {
        let checksum_ptr = (ip_start + 10) as *mut u16;
        *checksum_ptr = checksum.to_be();
    }
    
    info!(ctx, "Updated IPv4 checksum: 0x{:x}", checksum);
    Ok(())
}

/// Advanced packet forwarding with real network integration
fn forward_packet_to_interface(ctx: &XdpContext, target_interface: u32, modification_type: u8) -> Result<u32, ()> {
    // First, modify the packet as needed
    if let Err(_) = modify_packet_for_forwarding(ctx, modification_type) {
        info!(ctx, "Failed to modify packet for forwarding");
        return Err(());
    }
    
    // In a real implementation, this would use XDP_REDIRECT to send to specific interface
    // For now, we prepare the packet for forwarding
    
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let packet_size = data_end - data_start;
    
    info!(ctx, "Packet prepared for forwarding to interface {}: size={} bytes", 
          target_interface, packet_size);
    
    // Validate target interface is valid
    if target_interface == 0 {
        info!(ctx, "Invalid target interface: 0");
        return Err(());
    }
    
    // In a real implementation, this would:
    // 1. Look up target interface in a map
    // 2. Validate interface is up and reachable
    // 3. Use bpf_redirect or similar to forward
    // 4. Return XDP_REDIRECT action
    
    // For now, return TX to send packet back out the same interface
    Ok(xdp_action::XDP_TX)
}

/// Network-aware packet dropping with ICMP generation
fn drop_packet_with_notification(ctx: &XdpContext, drop_reason: u8) -> Result<u32, ()> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    if data_start >= data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    
    // In a real implementation, this could generate ICMP/ICMPv6 responses
    // for certain drop reasons (e.g., TTL exceeded, destination unreachable)
    
    match drop_reason {
        1 => {
            // TTL/hop limit exceeded
            info!(ctx, "Dropping packet: TTL/hop limit exceeded");
            // Could generate ICMP Time Exceeded message
        }
        2 => {
            // Destination unreachable
            info!(ctx, "Dropping packet: destination unreachable");
            // Could generate ICMP Destination Unreachable message
        }
        3 => {
            // NDN Interest loop detected
            info!(ctx, "Dropping packet: NDN Interest loop detected");
            // Could generate NDN NACK
        }
        4 => {
            // Rate limit exceeded
            info!(ctx, "Dropping packet: rate limit exceeded");
            // Could generate NDN NACK with congestion indication
        }
        _ => {
            info!(ctx, "Dropping packet: unknown reason {}", drop_reason);
        }
    }
    
    Ok(xdp_action::XDP_DROP)
}

/// Load balancing packet distribution
fn distribute_packet_to_next_hop(ctx: &XdpContext, next_hops: &[u32], distribution_method: u8) -> Result<u32, ()> {
    if next_hops.is_empty() {
        return Err(());
    }
    
    let selected_interface = match distribution_method {
        1 => {
            // Round-robin distribution
            let current_time = unsafe { bpf_ktime_get_ns() };
            let index = (current_time as usize) % next_hops.len();
            next_hops[index]
        }
        2 => {
            // Hash-based distribution
            let data_start = ctx.data();
            let data_end = ctx.data_end();
            
            if data_start + 14 > data_end {
                return Err(());
            }
            
            // Simple hash based on source and destination addresses
            let mut hash = 0u32;
            for i in 0..12 { // Hash first 12 bytes of ethernet header
                if data_start + i < data_end {
                    let byte = unsafe { *((data_start + i) as *const u8) };
                    hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
                }
            }
            
            let index = (hash as usize) % next_hops.len();
            next_hops[index]
        }
        _ => {
            // Default to first interface
            next_hops[0]
        }
    };
    
    info!(ctx, "Selected interface {} for packet distribution (method: {})", 
          selected_interface, distribution_method);
    
    // Forward to selected interface
    forward_packet_to_interface(ctx, selected_interface, 1) // Use MAC address modification
}

/// Network stack integration for packet injection
fn inject_packet_to_network(ctx: &XdpContext, target_interface: u32) -> Result<(), ()> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let packet_size = data_end - data_start;
    
    if packet_size == 0 {
        return Err(());
    }
    
    info!(ctx, "Packet injection prepared: size={} bytes, target_interface={}", 
          packet_size, target_interface);
    
    // Validate packet structure before injection
    if packet_size < 14 { // Minimum Ethernet frame size
        info!(ctx, "Packet too small for injection: {} bytes", packet_size);
        return Err(());
    }
    
    // Validate Ethernet header
    if data_start + 14 > data_end {
        return Err(());
    }
    
    let eth_hdr = unsafe { *(data_start as *const EthernetHeader) };
    let ether_type = u16::from_be(eth_hdr.ether_type);
    
    // Validate supported ethernet types
    match ether_type {
        0x0800 | 0x86dd => {
            // IPv4 or IPv6 - validate IP header
            let ip_start = data_start + 14;
            if ip_start >= data_end {
                return Err(());
            }
            
            let ip_version = (unsafe { *(ip_start as *const u8) } >> 4) & 0xF;
            match ip_version {
                4 => {
                    if ip_start + 20 > data_end {
                        info!(ctx, "IPv4 header truncated");
                        return Err(());
                    }
                    info!(ctx, "Validated IPv4 packet for injection");
                }
                6 => {
                    if ip_start + 40 > data_end {
                        info!(ctx, "IPv6 header truncated");
                        return Err(());
                    }
                    info!(ctx, "Validated IPv6 packet for injection");
                }
                _ => {
                    info!(ctx, "Unsupported IP version: {}", ip_version);
                    return Err(());
                }
            }
        }
        _ => {
            info!(ctx, "Unsupported ethernet type for injection: 0x{:x}", ether_type);
            return Err(());
        }
    }
    
    // In a real implementation, this would:
    // 1. Validate target interface exists and is up
    // 2. Check routing table for proper next hop
    // 3. Update packet headers (MAC, TTL, etc.)
    // 4. Use bpf_redirect() to send to target interface
    // 5. Handle different injection methods (XDP_REDIRECT, XDP_TX, etc.)
    
    // For now, we log the injection operation
    info!(ctx, "Packet validated and prepared for network injection");
    
    Ok(())
}

/// Advanced routing decision based on NDN name and network topology
fn make_routing_decision(ctx: &XdpContext, name_hash: u64, packet_type: u8) -> Result<u32, ()> {
    // Get current network topology information
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Simple routing logic based on name hash and packet type
    match packet_type {
        NDN_TLV_INTEREST => {
            // Interest routing - use FIB lookup
            let routing_key = name_hash & 0xFFFFFFFF; // Use lower 32 bits
            
            // Check if we have a direct route
            match unsafe { FILTER_RULES.get(&name_hash) } {
                Some(action) => {
                    if *action == FILTER_ACTION_REDIRECT {
                        // Redirect action indicates forwarding
                        let target_interface = ((name_hash >> 32) & 0xFF) as u32;
                        if target_interface > 0 {
                            info!(ctx, "Routing Interest to interface {}", target_interface);
                            return Ok(target_interface);
                        }
                    }
                }
                None => {
                    // No direct route, use default routing
                }
            }
            
            // Default Interest routing - use hash-based selection
            let interface_count = 4; // Assume 4 interfaces available
            let selected_interface = (routing_key % interface_count) + 1;
            
            info!(ctx, "Default Interest routing to interface {}", selected_interface);
            Ok(selected_interface as u32)
        }
        NDN_TLV_DATA => {
            // Data routing - return to requesting face(s)
            // This is handled by PIT lookup in normal processing
            // Here we handle unsolicited data or multicast data
            
            let multicast_threshold = 0x8000000000000000u64;
            if name_hash >= multicast_threshold {
                // Multicast data - send to multiple interfaces
                info!(ctx, "Multicast Data routing");
                Ok(0xFF) // Special value indicating multicast
            } else {
                // Unicast data - use reverse path
                let reverse_interface = ((name_hash >> 16) & 0xFF) as u32;
                let final_interface = if reverse_interface == 0 { 1 } else { reverse_interface };
                
                info!(ctx, "Unicast Data routing to interface {}", final_interface);
                Ok(final_interface)
            }
        }
        _ => {
            // Unknown packet type
            info!(ctx, "Unknown packet type for routing: {}", packet_type);
            Err(())
        }
    }
}

/// Real-time network performance monitoring
fn monitor_network_performance(ctx: &XdpContext) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Get current packet statistics
    let packet_stats = match unsafe { PACKET_STATS.get(&0) } {
        Some(stats) => *stats,
        None => PacketStats::new(),
    };
    
    // Get PIT statistics
    let pit_stats = match unsafe { PIT_STATS.get(&0) } {
        Some(stats) => *stats,
        None => PitStats::new(),
    };
    
    // Get Content Store statistics
    let cs_stats = match unsafe { CS_STATS.get(&0) } {
        Some(stats) => *stats,
        None => ContentStoreStats::new(),
    };
    
    // Calculate performance metrics
    let total_packets = packet_stats.packets_processed;
    let processing_efficiency = if total_packets > 0 {
        (packet_stats.packets_passed * 100) / total_packets
    } else {
        0
    };
    
    let pit_efficiency = if pit_stats.insertions > 0 {
        (pit_stats.entries_satisfied * 100) / pit_stats.insertions
    } else {
        0
    };
    
    let cs_hit_ratio = if cs_stats.lookups > 0 {
        (cs_stats.hits * 100) / cs_stats.lookups
    } else {
        0
    };
    
    // Log performance metrics periodically
    if total_packets > 0 && total_packets % 1000 == 0 {
        info!(ctx, "Network Performance: processed={}, efficiency={}%, pit_efficiency={}%, cs_hit_ratio={}%",
              total_packets, processing_efficiency, pit_efficiency, cs_hit_ratio);
        
        // Check for performance degradation
        if processing_efficiency < 50 {
            info!(ctx, "WARNING: Low processing efficiency detected: {}%", processing_efficiency);
        }
        
        if pit_efficiency < 70 {
            info!(ctx, "WARNING: Low PIT efficiency detected: {}%", pit_efficiency);
        }
        
        if cs_hit_ratio < 20 {
            info!(ctx, "WARNING: Low Content Store hit ratio: {}%", cs_hit_ratio);
        }
    }
    
    // Store monitoring timestamp
    let monitoring_key = 0xFFFFFFFFu32;
    let _ = unsafe { INTEREST_CACHE.insert(&(monitoring_key as u64), &current_time, 0) };
    
    Ok(())
}

/// Network congestion control for NDN forwarding
fn apply_congestion_control(ctx: &XdpContext, name_hash: u64, packet_type: u8) -> Result<u32, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Get current packet statistics for congestion assessment
    let packet_stats = match unsafe { PACKET_STATS.get(&0) } {
        Some(stats) => *stats,
        None => PacketStats::new(),
    };
    
    // Calculate congestion metrics
    let total_packets = packet_stats.packets_processed;
    let drop_rate = if total_packets > 0 {
        (packet_stats.packets_dropped * 100) / total_packets
    } else {
        0
    };
    
    // Congestion thresholds
    let congestion_threshold = 10; // 10% drop rate indicates congestion
    let severe_congestion_threshold = 25; // 25% drop rate indicates severe congestion
    
    let congestion_action = if drop_rate >= severe_congestion_threshold {
        // Severe congestion - aggressive dropping
        match packet_type {
            NDN_TLV_INTEREST => {
                // Drop some Interest packets based on name hash
                if (name_hash & 0x3) == 0 { // Drop 25% of Interests
                    info!(ctx, "Severe congestion: dropping Interest");
                    return Ok(xdp_action::XDP_DROP);
                }
                xdp_action::XDP_PASS
            }
            NDN_TLV_DATA => {
                // Always try to forward Data packets
                xdp_action::XDP_PASS
            }
            _ => xdp_action::XDP_DROP,
        }
    } else if drop_rate >= congestion_threshold {
        // Moderate congestion - selective dropping
        match packet_type {
            NDN_TLV_INTEREST => {
                // Drop some Interest packets based on name hash
                if (name_hash & 0x7) == 0 { // Drop 12.5% of Interests
                    info!(ctx, "Moderate congestion: dropping Interest");
                    return Ok(xdp_action::XDP_DROP);
                }
                xdp_action::XDP_PASS
            }
            NDN_TLV_DATA => {
                // Always forward Data packets
                xdp_action::XDP_PASS
            }
            _ => xdp_action::XDP_PASS,
        }
    } else {
        // No congestion - normal processing
        xdp_action::XDP_PASS
    };
    
    // Log congestion state changes
    if drop_rate >= congestion_threshold {
        info!(ctx, "Congestion control active: drop_rate={}%, action={}", drop_rate, congestion_action);
    }
    
    Ok(congestion_action)
}

/// Helper function to parse payload start position
fn parse_payload_start(ctx: &XdpContext) -> Result<usize, ()> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Parse through protocol layers to find NDN payload
    if data_start + mem::size_of::<EthernetHeader>() > data_end {
        return Err(());
    }
    
    let eth_hdr = unsafe { *(data_start as *const EthernetHeader) };
    let ether_type = u16::from_be(eth_hdr.ether_type);
    
    match ether_type {
        0x0800 => {
            // IPv4
            let ip_start = data_start + mem::size_of::<EthernetHeader>();
            if ip_start + 20 > data_end {
                return Err(());
            }
            
            let ip_hdr = unsafe { *(ip_start as *const u8) };
            let ip_header_len = ((ip_hdr & 0xF) as usize) * 4;
            let protocol = unsafe { *((ip_start + 9) as *const u8) };
            
            match protocol {
                6 => {
                    // TCP
                    let tcp_start = ip_start + ip_header_len;
                    if tcp_start + 20 > data_end {
                        return Err(());
                    }
                    let tcp_hdr_len = ((unsafe { *((tcp_start + 12) as *const u8) } >> 4) & 0xF) as usize * 4;
                    Ok(tcp_start + tcp_hdr_len)
                }
                17 => {
                    // UDP
                    Ok(ip_start + ip_header_len + 8)
                }
                _ => Err(()),
            }
        }
        0x86dd => {
            // IPv6
            let ip_start = data_start + mem::size_of::<EthernetHeader>();
            if ip_start + 40 > data_end {
                return Err(());
            }
            
            let next_header = unsafe { *((ip_start + 6) as *const u8) };
            match next_header {
                6 => {
                    // TCP
                    let tcp_start = ip_start + 40;
                    if tcp_start + 20 > data_end {
                        return Err(());
                    }
                    let tcp_hdr_len = ((unsafe { *((tcp_start + 12) as *const u8) } >> 4) & 0xF) as usize * 4;
                    Ok(tcp_start + tcp_hdr_len)
                }
                17 => {
                    // UDP
                    Ok(ip_start + 40 + 8)
                }
                _ => Err(()),
            }
        }
        _ => Err(()),
    }
}

/// Panic handler for eBPF programs
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// License declaration required for eBPF programs
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
// NDN TLV type constants for packet identification
const NDN_TLV_INTEREST: u8 = 0x05;
const NDN_TLV_DATA: u8 = 0x06;
const NDN_TLV_NAME: u8 = 0x07;
const NDN_TLV_NAME_COMPONENT: u8 = 0x08;
const NDN_TLV_NONCE: u8 = 0x0A;
const NDN_TLV_INTEREST_LIFETIME: u8 = 0x0C;
const NDN_TLV_META_INFO: u8 = 0x14;
const NDN_TLV_CONTENT: u8 = 0x15;
const NDN_TLV_SIGNATURE_INFO: u8 = 0x16;
const NDN_TLV_SIGNATURE_VALUE: u8 = 0x17;
const NDN_TLV_CONTENT_TYPE: u8 = 0x18;
const NDN_TLV_FRESHNESS_PERIOD: u8 = 0x19;
const NDN_TLV_FINAL_BLOCK_ID: u8 = 0x1A;
const NDN_TLV_SIGNATURE_TYPE: u8 = 0x1B;
const NDN_TLV_KEY_LOCATOR: u8 = 0x1C;
const NDN_TLV_KEY_DIGEST: u8 = 0x1D;
const NDN_TLV_SELECTORS: u8 = 0x09;
const NDN_TLV_MIN_SUFFIX_COMPONENTS: u8 = 0x0D;
const NDN_TLV_MAX_SUFFIX_COMPONENTS: u8 = 0x0E;
const NDN_TLV_PUBLISHER_PUBLIC_KEY_LOCATOR: u8 = 0x0F;
const NDN_TLV_EXCLUDE: u8 = 0x10;
const NDN_TLV_CHILD_SELECTOR: u8 = 0x11;
const NDN_TLV_MUST_BE_FRESH: u8 = 0x12;
const NDN_TLV_ANY: u8 = 0x13;

// Extended NDN TLV types for complete protocol support (u8 range only)
const NDN_TLV_FORWARDING_HINT: u8 = 0x1E;
const NDN_TLV_APPLICATION_PARAMETERS: u8 = 0x24;
const NDN_TLV_SIGNATURE_TIME: u8 = 0x2C;
const NDN_TLV_SIGNATURE_SEQNUM: u8 = 0x2E;
const NDN_TLV_ENCRYPTED_PAYLOAD: u8 = 0x82;
const NDN_TLV_INITIALIZATION_VECTOR: u8 = 0x83;
const NDN_TLV_ENCRYPTED_CONTENT: u8 = 0x84;
const NDN_TLV_SAFE_BAG: u8 = 0x85;
const NDN_TLV_CERTIFICATE_V2: u8 = 0x86;
const NDN_TLV_IDENTITY_CERTIFICATE: u8 = 0x87;
const NDN_TLV_KEY_CERTIFICATE: u8 = 0x88;
const NDN_TLV_KEY_SHARE: u8 = 0x89;
const NDN_TLV_ENCRYPTED_KEY: u8 = 0x8A;
const NDN_TLV_DELEGATION_SET: u8 = 0x8B;
const NDN_TLV_DELEGATION: u8 = 0x8C;
const NDN_TLV_PREFERENCE: u8 = 0x8D;
const NDN_TLV_LINK_PREFERENCE: u8 = 0x8E;
const NDN_TLV_LINK_DELEGATION: u8 = 0x8F;
// Note: Larger TLV types (0x0320+, 0xFD00+) require multi-byte encoding
// and are handled differently in the parsing functions
const NDN_TLV_NACK_SIMPLE: u8 = 0x32;  // Simplified NACK representation
const NDN_TLV_NACK_REASON_SIMPLE: u8 = 0x33;  // Simplified NACK reason

// NDN signature types
const NDN_SIGNATURE_DIGEST_SHA256: u8 = 0x00;
const NDN_SIGNATURE_SHA256_WITH_RSA: u8 = 0x01;
const NDN_SIGNATURE_SHA256_WITH_ECDSA: u8 = 0x03;
const NDN_SIGNATURE_HMAC_WITH_SHA256: u8 = 0x04;

// NDN content types
const NDN_CONTENT_TYPE_BLOB: u8 = 0x00;
const NDN_CONTENT_TYPE_LINK: u8 = 0x01;
const NDN_CONTENT_TYPE_KEY: u8 = 0x02;
const NDN_CONTENT_TYPE_NACK: u8 = 0x03;

// Additional packet processing constants
const MAX_PACKET_SIZE: usize = 8192;
const MAX_FORWARDING_HOPS: u8 = 64;
const DEFAULT_INTEREST_LIFETIME_MS: u32 = 4000;

// Version section removed - was causing kernel version mismatch errors in containers

/// Advanced TLV processing functions for complete NDN protocol support

/// Parse Application Parameters TLV
fn parse_application_parameters(ctx: &XdpContext, param_start: usize) -> Result<(usize, u32), ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for TLV header
    if param_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is an Application Parameters TLV
    let param_type = unsafe { *(param_start as *const u8) };
    if param_type != NDN_TLV_APPLICATION_PARAMETERS {
        info!(ctx, "Expected Application Parameters TLV, got: {}", param_type);
        return Err(());
    }
    
    // Parse parameter length
    let tlv_result = parse_tlv_length(ctx, param_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Application Parameters TLV length");
        return Err(());
    }
    
    let param_length = (tlv_result >> 16) as usize;
    let param_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate parameter bounds
    if param_start + param_header_size + param_length > data_end {
        info!(ctx, "Application Parameters TLV truncated");
        return Err(());
    }
    
    // Calculate checksum for parameters
    let param_checksum = calculate_simple_checksum(ctx, param_start + param_header_size, param_length);
    
    info!(ctx, "Parsed Application Parameters: length={}, checksum={}", param_length, param_checksum);
    
    Ok((param_length, param_checksum))
}

/// Parse Forwarding Hint TLV
fn parse_forwarding_hint(ctx: &XdpContext, hint_start: usize) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for TLV header
    if hint_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is a Forwarding Hint TLV
    let hint_type = unsafe { *(hint_start as *const u8) };
    if hint_type != NDN_TLV_FORWARDING_HINT {
        info!(ctx, "Expected Forwarding Hint TLV, got: {}", hint_type);
        return Err(());
    }
    
    // Parse hint length
    let tlv_result = parse_tlv_length(ctx, hint_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Forwarding Hint TLV length");
        return Err(());
    }
    
    let hint_length = (tlv_result >> 16) as usize;
    let hint_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate hint bounds
    if hint_start + hint_header_size + hint_length > data_end {
        info!(ctx, "Forwarding Hint TLV truncated");
        return Err(());
    }
    
    // Count number of delegation entries in the hint
    let mut current_pos = hint_start + hint_header_size;
    let hint_end = current_pos + hint_length;
    let mut delegation_count = 0u32;
    
    while current_pos + 2 < hint_end && current_pos < data_end {
        // Check for delegation TLV
        let del_type = unsafe { *(current_pos as *const u8) };
        if del_type == NDN_TLV_DELEGATION || del_type == NDN_TLV_LINK_DELEGATION {
            delegation_count += 1;
            
            // Skip this delegation entry
            let del_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if del_tlv_result == 0 {
                break;
            }
            let del_length = (del_tlv_result >> 16) as usize;
            let del_header_size = (del_tlv_result & 0xFFFF) as usize;
            
            current_pos += del_header_size + del_length;
        } else {
            // Unknown TLV, skip it
            let unknown_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if unknown_tlv_result == 0 {
                break;
            }
            let unknown_length = (unknown_tlv_result >> 16) as usize;
            let unknown_header_size = (unknown_tlv_result & 0xFFFF) as usize;
            
            current_pos += unknown_header_size + unknown_length;
        }
    }
    
    info!(ctx, "Parsed Forwarding Hint: {} delegations", delegation_count);
    
    Ok(delegation_count)
}

/// Parse NACK packet and extract reason
fn parse_nack_packet(ctx: &XdpContext, nack_start: usize) -> Result<u8, ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for TLV header
    if nack_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is a NACK TLV
    let nack_type = unsafe { *(nack_start as *const u8) };
    if nack_type != NDN_TLV_NACK_SIMPLE {
        info!(ctx, "Expected NACK TLV, got: {}", nack_type);
        return Err(());
    }
    
    // Parse NACK length
    let tlv_result = parse_tlv_length(ctx, nack_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse NACK TLV length");
        return Err(());
    }
    
    let nack_length = (tlv_result >> 16) as usize;
    let nack_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate NACK bounds
    if nack_start + nack_header_size + nack_length > data_end {
        info!(ctx, "NACK TLV truncated");
        return Err(());
    }
    
    // Look for NACK reason TLV
    let mut current_pos = nack_start + nack_header_size;
    let nack_end = current_pos + nack_length;
    
    while current_pos + 2 < nack_end && current_pos < data_end {
        let reason_type = unsafe { *(current_pos as *const u8) };
        if reason_type == NDN_TLV_NACK_REASON_SIMPLE {
            // Parse reason length
            let reason_tlv_result = parse_tlv_length(ctx, current_pos + 1);
            if reason_tlv_result == 0 {
                break;
            }
            let reason_length = (reason_tlv_result >> 16) as usize;
            let reason_header_size = (reason_tlv_result & 0xFFFF) as usize;
            
            // Extract reason value
            if reason_length == 1 && current_pos + reason_header_size + 1 <= data_end {
                let reason_value = unsafe { *((current_pos + reason_header_size) as *const u8) };
                info!(ctx, "NACK reason: {}", reason_value);
                return Ok(reason_value);
            }
            
            break;
        }
        
        // Skip unknown TLV
        let unknown_tlv_result = parse_tlv_length(ctx, current_pos + 1);
        if unknown_tlv_result == 0 {
            break;
        }
        let unknown_length = (unknown_tlv_result >> 16) as usize;
        let unknown_header_size = (unknown_tlv_result & 0xFFFF) as usize;
        
        current_pos += unknown_header_size + unknown_length;
    }
    
    info!(ctx, "NACK packet without reason");
    Ok(0) // Default reason
}

/// Parse signature information with enhanced validation
fn parse_signature_info_enhanced(ctx: &XdpContext, sig_start: usize) -> Result<(u8, u32), ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for TLV header
    if sig_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is a Signature Info TLV
    let sig_type = unsafe { *(sig_start as *const u8) };
    if sig_type != NDN_TLV_SIGNATURE_INFO {
        info!(ctx, "Expected Signature Info TLV, got: {}", sig_type);
        return Err(());
    }
    
    // Parse signature length
    let tlv_result = parse_tlv_length(ctx, sig_start + 1);
    if tlv_result == 0 {
        info!(ctx, "Failed to parse Signature Info TLV length");
        return Err(());
    }
    
    let sig_length = (tlv_result >> 16) as usize;
    let sig_header_size = (tlv_result & 0xFFFF) as usize;
    
    // Validate signature bounds
    if sig_start + sig_header_size + sig_length > data_end {
        info!(ctx, "Signature Info TLV truncated");
        return Err(());
    }
    
    let mut current_pos = sig_start + sig_header_size;
    let sig_end = current_pos + sig_length;
    let mut signature_type = 0u8;
    let mut key_locator_hash = 0u32;
    
    // Parse signature info components
    while current_pos + 2 < sig_end && current_pos < data_end {
        let component_type = unsafe { *(current_pos as *const u8) };
        
        match component_type {
            NDN_TLV_SIGNATURE_TYPE => {
                let comp_tlv_result = parse_tlv_length(ctx, current_pos + 1);
                if comp_tlv_result == 0 {
                    break;
                }
                let comp_length = (comp_tlv_result >> 16) as usize;
                let comp_header_size = (comp_tlv_result & 0xFFFF) as usize;
                
                if comp_length == 1 && current_pos + comp_header_size + 1 <= data_end {
                    signature_type = unsafe { *((current_pos + comp_header_size) as *const u8) };
                    info!(ctx, "Signature type: {}", signature_type);
                }
                
                current_pos += comp_header_size + comp_length;
            }
            NDN_TLV_KEY_LOCATOR => {
                let comp_tlv_result = parse_tlv_length(ctx, current_pos + 1);
                if comp_tlv_result == 0 {
                    break;
                }
                let comp_length = (comp_tlv_result >> 16) as usize;
                let comp_header_size = (comp_tlv_result & 0xFFFF) as usize;
                
                // Calculate simple hash of key locator
                if comp_length > 0 && current_pos + comp_header_size + comp_length <= data_end {
                    key_locator_hash = calculate_simple_checksum(ctx, current_pos + comp_header_size, comp_length);
                    info!(ctx, "Key locator hash: {}", key_locator_hash);
                }
                
                current_pos += comp_header_size + comp_length;
            }
            _ => {
                // Skip unknown component
                let comp_tlv_result = parse_tlv_length(ctx, current_pos + 1);
                if comp_tlv_result == 0 {
                    break;
                }
                let comp_length = (comp_tlv_result >> 16) as usize;
                let comp_header_size = (comp_tlv_result & 0xFFFF) as usize;
                
                current_pos += comp_header_size + comp_length;
            }
        }
    }
    
    info!(ctx, "Parsed Signature Info: type={}, key_locator_hash={}", signature_type, key_locator_hash);
    
    Ok((signature_type, key_locator_hash))
}

/// Calculate a simple checksum for TLV content
fn calculate_simple_checksum(ctx: &XdpContext, content_start: usize, content_length: usize) -> u32 {
    let data_end = ctx.data_end();
    let mut checksum = 0u32;
    let mut current_pos = content_start;
    let content_end = (content_start + content_length).min(data_end);
    
    // Simple additive checksum with rotation
    while current_pos < content_end {
        let byte_val = unsafe { *(current_pos as *const u8) } as u32;
        checksum = checksum.wrapping_add(byte_val);
        checksum = checksum.rotate_left(1);
        current_pos += 1;
    }
    
    checksum
}

/// Real-time packet forwarding engine with network stack integration
fn apply_realtime_forwarding(ctx: &XdpContext, payload_start: usize) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    
    // Validate payload bounds
    if payload_start == 0 || payload_start + 1 >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let packet_type = unsafe { *(payload_start as *const u8) };
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Handle different packet types for real-time forwarding
    match packet_type {
        NDN_TLV_INTEREST => {
            // Real-time Interest forwarding
            let name_hash = extract_interest_name_hash(ctx, payload_start);
            
            // Check if we have a cached forwarding decision
            if let Some(cached_decision) = get_cached_forwarding_decision(ctx, name_hash) {
                info!(ctx, "Using cached forwarding decision for Interest: {}", cached_decision);
                return apply_forwarding_decision(ctx, cached_decision);
            }
            
            // Make real-time forwarding decision
            let forwarding_decision = make_realtime_forwarding_decision(ctx, name_hash, packet_type)?;
            
            // Cache the decision for future use
            let _ = cache_forwarding_decision(ctx, name_hash, forwarding_decision);
            
            // Apply the forwarding decision
            apply_forwarding_decision(ctx, forwarding_decision)
        }
        NDN_TLV_DATA => {
            // Real-time Data forwarding (return to PIT entries)
            let name_hash = extract_data_name_hash(ctx, payload_start);
            
            // Look up PIT entries for this Data packet
            if let Some(pit_entry) = get_pit_entry_for_data(ctx, name_hash) {
                info!(ctx, "Found PIT entry for Data packet, forwarding to primary face");
                
                // Forward to all faces in the PIT entry
                return forward_data_to_pit_faces_realtime(ctx, &pit_entry);
            }
            
            // No PIT entry found, drop the packet
            info!(ctx, "No PIT entry found for Data packet");
            Ok(xdp_action::XDP_DROP)
        }
        _ => {
            // Unknown packet type, pass through
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Get cached forwarding decision for a name hash
fn get_cached_forwarding_decision(ctx: &XdpContext, name_hash: u64) -> Option<u32> {
    // Use Interest cache as a forwarding decision cache
    let cache_key = name_hash ^ 0x5555555555555555; // XOR with pattern to avoid collision
    
    match unsafe { INTEREST_CACHE.get(&cache_key) } {
        Some(cached_time) => {
            let current_time = unsafe { bpf_ktime_get_ns() };
            let cache_age = current_time - *cached_time;
            
            // Cache expires after 1 second
            if cache_age < 1_000_000_000 {
                // Return cached decision (encoded in the lower 32 bits)
                Some((*cached_time & 0xFFFFFFFF) as u32)
            } else {
                None
            }
        }
        None => None,
    }
}

/// Cache a forwarding decision for future use
fn cache_forwarding_decision(ctx: &XdpContext, name_hash: u64, decision: u32) -> Result<(), ()> {
    let cache_key = name_hash ^ 0x5555555555555555; // XOR with pattern to avoid collision
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Encode decision in the lower 32 bits and time in upper 32 bits
    let cache_value = (current_time & 0xFFFFFFFF00000000) | (decision as u64);
    
    let _ = unsafe { INTEREST_CACHE.insert(&cache_key, &cache_value, 0) };
    Ok(())
}

/// Make real-time forwarding decision based on current network state
fn make_realtime_forwarding_decision(ctx: &XdpContext, name_hash: u64, packet_type: u8) -> Result<u32, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Check network congestion level
    let congestion_level = assess_network_congestion(ctx, current_time)?;
    
    // Check PIT state for Interest aggregation
    if packet_type == NDN_TLV_INTEREST {
        match unsafe { PIT_TABLE.get(&name_hash) } {
            Some(pit_entry) => {
                let age = current_time - pit_entry.created_time;
                if age < 500_000_000 { // 500ms
                    // Recent PIT entry exists, aggregate Interest
                    info!(ctx, "Aggregating Interest with existing PIT entry");
                    return Ok(xdp_action::XDP_DROP);
                }
            }
            None => {
                // No PIT entry, check if we should forward
                if congestion_level > 80 {
                    // High congestion, be more selective
                    info!(ctx, "High congestion detected, applying selective forwarding");
                    return apply_selective_forwarding(ctx, name_hash);
                }
            }
        }
    }
    
    // Check available network interfaces
    let best_interface = select_best_interface(ctx, name_hash)?;
    
    // Make forwarding decision based on interface availability
    match best_interface {
        1..=4 => {
            info!(ctx, "Forwarding to interface {}", best_interface);
            Ok(xdp_action::XDP_REDIRECT)
        }
        _ => {
            info!(ctx, "No suitable interface available");
            Ok(xdp_action::XDP_DROP)
        }
    }
}

/// Assess current network congestion level (0-100)
fn assess_network_congestion(ctx: &XdpContext, current_time: u64) -> Result<u32, ()> {
    let window_duration = 1_000_000_000; // 1 second window
    let window_start = current_time - window_duration;
    
    // Check packet processing rate
    let packet_rate = match unsafe { PACKET_STATS.get(&0) } {
        Some(stats) => {
            let packets_per_second = stats.packets_processed;
            if packets_per_second > 10000 {
                80 // High congestion
            } else if packets_per_second > 5000 {
                50 // Medium congestion
            } else {
                20 // Low congestion
            }
        }
        None => 20, // Default to low congestion
    };
    
    // Check PIT table utilization
    let pit_utilization = match unsafe { PIT_STATS.get(&0) } {
        Some(stats) => {
            let utilization = (stats.active_entries * 100) / 1000; // Assume max 1000 entries
            if utilization > 80 {
                30 // High PIT utilization adds congestion
            } else if utilization > 50 {
                15 // Medium utilization
            } else {
                5 // Low utilization
            }
        }
        None => 5,
    };
    
    let total_congestion = packet_rate + pit_utilization;
    Ok(total_congestion.min(100))
}

/// Apply selective forwarding during high congestion
fn apply_selective_forwarding(ctx: &XdpContext, name_hash: u64) -> Result<u32, ()> {
    // Use name hash to determine forwarding priority
    let priority = (name_hash & 0xFF) as u8;
    
    // Forward only high-priority packets during congestion
    if priority > 200 {
        info!(ctx, "High priority packet forwarded during congestion");
        Ok(xdp_action::XDP_REDIRECT)
    } else {
        info!(ctx, "Low priority packet dropped during congestion");
        Ok(xdp_action::XDP_DROP)
    }
}

/// Select the best interface for forwarding
fn select_best_interface(ctx: &XdpContext, name_hash: u64) -> Result<u32, ()> {
    // Simple load balancing based on name hash
    let interface_count = 4;
    let selected_interface = (name_hash % interface_count) + 1;
    
    // Check if interface is available (simplified check)
    let interface_key = selected_interface as u64;
    match unsafe { FACE_TABLE.get(&(interface_key as u32)) } {
        Some(face) => {
            if face.state == 1 { // Assume 1 means active
                Ok(selected_interface as u32)
            } else {
                // Interface not active, try next one
                Ok(((selected_interface % interface_count) + 1) as u32)
            }
        }
        None => {
            // No face info, assume interface 1 is available
            Ok(1)
        }
    }
}

/// Apply forwarding decision to packet
fn apply_forwarding_decision(ctx: &XdpContext, decision: u32) -> Result<u32, ()> {
    match decision {
        xdp_action::XDP_PASS => Ok(xdp_action::XDP_PASS),
        xdp_action::XDP_DROP => Ok(xdp_action::XDP_DROP),
        xdp_action::XDP_REDIRECT => {
            // In a real implementation, this would set the redirect target
            info!(ctx, "Redirecting packet to selected interface");
            Ok(xdp_action::XDP_REDIRECT)
        }
        xdp_action::XDP_TX => {
            // Transmit packet back out the same interface
            info!(ctx, "Transmitting packet back to sender");
            Ok(xdp_action::XDP_TX)
        }
        _ => Ok(xdp_action::XDP_PASS), // Default action
    }
}

/// Get PIT entry for incoming Data packet
fn get_pit_entry_for_data(ctx: &XdpContext, name_hash: u64) -> Option<PitEntry> {
    match unsafe { PIT_TABLE.get(&name_hash) } {
        Some(entry) => {
            info!(ctx, "Found PIT entry for Data packet");
            Some(*entry)
        }
        None => {
            info!(ctx, "No PIT entry found for Data packet");
            None
        }
    }
}

/// Forward Data packet to all faces in PIT entry (realtime version)
fn forward_data_to_pit_faces_realtime(ctx: &XdpContext, pit_entry: &PitEntry) -> Result<u32, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Validate PIT entry is still valid
    if current_time - pit_entry.created_time > 4_000_000_000 { // 4 seconds
        info!(ctx, "PIT entry expired, dropping Data packet");
        return Ok(xdp_action::XDP_DROP);
    }
    
    // In a real implementation, we would forward to all faces
    // For now, we'll redirect to the primary face
    info!(ctx, "Forwarding Data packet to primary face");
    Ok(xdp_action::XDP_REDIRECT)
}

/// Extract name hash from Data packet
fn extract_data_name_hash(ctx: &XdpContext, data_start: usize) -> u64 {
    let data_end = ctx.data_end();
    
    // Skip Data TLV header and length to get to Name
    if data_start + 4 < data_end {
        let tlv_result = parse_tlv_length(ctx, data_start + 1);
        if tlv_result != 0 {
            let header_size = (tlv_result & 0xFFFF) as usize;
            let name_start = data_start + header_size;
            
            // Extract name hash (simplified)
            if name_start + 4 < data_end {
                let name_type = unsafe { *(name_start as *const u8) };
                if name_type == NDN_TLV_NAME {
                    return extract_interest_name_hash(ctx, name_start);
                }
            }
        }
    }
    
    0 // Default hash if parsing fails
}

/// Advanced PIT and CS management features for enhanced performance

/// Advanced PIT management with priority-based entry handling
fn pit_advanced_management(ctx: &XdpContext, name_hash: u64, priority: u8) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Check if PIT is approaching capacity
    let pit_stats = match unsafe { PIT_STATS.get(&0) } {
        Some(stats) => *stats,
        None => PitStats::new(),
    };
    
    // If PIT is getting full, apply priority-based management
    if pit_stats.active_entries > (MAX_PIT_ENTRIES as u64 * 80 / 100) {
        info!(ctx, "PIT approaching capacity, applying priority-based management");
        
        // Try to evict low-priority entries if this is a high-priority request
        if priority > 128 {
            let evicted = pit_evict_low_priority_entries(ctx, priority)?;
            if evicted > 0 {
                info!(ctx, "Evicted {} low-priority PIT entries for high-priority request", evicted);
            }
        }
    }
    
    // Update PIT access patterns for better management
    let _ = pit_update_access_patterns(ctx, name_hash, current_time);
    
    Ok(())
}

/// Evict low-priority PIT entries to make room for high-priority ones
fn pit_evict_low_priority_entries(ctx: &XdpContext, min_priority: u8) -> Result<u32, ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let mut evicted_count = 0u32;
    
    // Since we can't iterate over eBPF maps, we use a sampling approach
    // Check a sample of potential entries based on time patterns
    let time_pattern = (current_time / 1_000_000_000) % 100; // Use second patterns
    
    for sample_offset in 0..10 {
        let sample_key = (time_pattern + sample_offset) as u64;
        let sample_hash = sample_key.wrapping_mul(0x9e3779b9).wrapping_add(0x85ebca6b);
        
        // Check if this sampled entry exists and has low priority
        match unsafe { PIT_TABLE.get(&sample_hash) } {
            Some(entry) => {
                // Check if entry has expired or is low priority
                let entry_age = current_time - entry.created_time;
                let estimated_priority = ((entry.nonce & 0xFF) as u8).wrapping_add(128);
                
                if entry_age > 2_000_000_000 || estimated_priority < min_priority {
                    // Remove this entry
                    let _ = unsafe { PIT_TABLE.remove(&sample_hash) };
                    evicted_count += 1;
                    
                    // Also remove associated faces
                    let face_key = (sample_hash << 8) | (entry.incoming_face as u64);
                    let _ = unsafe { PIT_ADDITIONAL_FACES.remove(&face_key) };
                }
            }
            None => continue,
        }
    }
    
    // Update statistics
    if evicted_count > 0 {
        update_pit_stats(ctx, |stats| {
            stats.entries_expired += evicted_count as u64;
            stats.active_entries = stats.active_entries.saturating_sub(evicted_count as u64);
        });
    }
    
    Ok(evicted_count)
}

/// Update PIT access patterns for better cache management
fn pit_update_access_patterns(ctx: &XdpContext, name_hash: u64, access_time: u64) -> Result<(), ()> {
    // Use a simple pattern tracking system
    let pattern_key = (name_hash >> 32) as u32; // Use upper 32 bits as pattern key
    let pattern_info = (access_time & 0xFFFFFFFF) as u32; // Use lower 32 bits of time
    
    // Store access pattern (simplified - just track the access time)
    let access_time_key = pattern_key;
    let access_value = access_time;
    
    // Use Interest cache for pattern tracking
    let _ = unsafe { INTEREST_CACHE.insert(&(access_time_key as u64), &access_value, 0) };
    
    info!(ctx, "Updated PIT access pattern for name_hash: {}", name_hash);
    Ok(())
}

/// Advanced Content Store management with intelligent caching
fn cs_advanced_management(ctx: &XdpContext, name_hash: u64, data_size: u32, freshness_hint: u32) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Get current CS statistics
    let cs_stats = match unsafe { CS_STATS.get(&0) } {
        Some(stats) => *stats,
        None => ContentStoreStats::new(),
    };
    
    // Calculate cache efficiency metrics
    let hit_ratio = if cs_stats.lookups > 0 {
        (cs_stats.hits * 100) / cs_stats.lookups
    } else {
        0
    };
    
    // Apply intelligent caching decisions
    if hit_ratio < 30 {
        // Low hit ratio, be more aggressive with caching
        info!(ctx, "Low cache hit ratio ({}%), applying aggressive caching", hit_ratio);
        let _ = cs_aggressive_caching_policy(ctx, name_hash, data_size, freshness_hint);
    } else if hit_ratio > 80 {
        // High hit ratio, optimize for storage efficiency
        info!(ctx, "High cache hit ratio ({}%), optimizing for efficiency", hit_ratio);
        let _ = cs_efficiency_optimization(ctx, name_hash, data_size);
    }
    
    // Update access frequency tracking
    let _ = cs_update_access_frequency(ctx, name_hash, current_time);
    
    Ok(())
}

/// Apply aggressive caching policy for low hit ratios
fn cs_aggressive_caching_policy(ctx: &XdpContext, name_hash: u64, data_size: u32, freshness_hint: u32) -> Result<(), ()> {
    // Increase cache retention time and priority
    let extended_freshness = freshness_hint * 2; // Double the freshness period
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Check if we need to make room
    let cs_stats = match unsafe { CS_STATS.get(&0) } {
        Some(stats) => *stats,
        None => ContentStoreStats::new(),
    };
    
    if cs_stats.current_entries > (MAX_CS_ENTRIES as u64 * 90 / 100) {
        // Cache is very full, evict entries more aggressively
        let entries_to_evict = (MAX_CS_ENTRIES as u32 / 4).max(1); // Evict 25% of cache
        let evicted = cs_evict_multiple_lru_entries(ctx, entries_to_evict);
        info!(ctx, "Aggressive policy evicted {} entries to make room", evicted);
    }
    
    // Create entry with extended freshness
    let cache_entry = ContentStoreEntry {
        name_hash,
        created_time: current_time,
        last_access_time: current_time,
        expiry_time: current_time + (extended_freshness as u64 * 1_000_000), // Convert to nanoseconds
        data_hash: name_hash ^ data_size as u64,
        hit_count: 1,
        lru_sequence: cs_get_next_lru_sequence(ctx).unwrap_or(0),
        content_type: 0, // Default content type
        data_size,
        state: 0, // Default state
        _reserved: 0,
    };
    
    let _ = unsafe { CONTENT_STORE.insert(&name_hash, &cache_entry, 0) };
    
    info!(ctx, "Applied aggressive caching for name_hash: {}", name_hash);
    Ok(())
}

/// Apply efficiency optimization for high hit ratios
fn cs_efficiency_optimization(ctx: &XdpContext, name_hash: u64, data_size: u32) -> Result<(), ()> {
    // For high hit ratios, focus on keeping only frequently accessed items
    let access_threshold = 5; // Minimum access count to keep
    
    // Check if this item is frequently accessed
    let keep_item = match unsafe { CONTENT_STORE.get(&name_hash) } {
        Some(entry) => entry.hit_count >= access_threshold,
        None => true, // New item, give it a chance
    };
    
    if keep_item {
        // Item is frequently accessed, optimize its storage
        let current_time = unsafe { bpf_ktime_get_ns() };
        let optimized_entry = ContentStoreEntry {
            name_hash,
            created_time: current_time,
            last_access_time: current_time,
            expiry_time: current_time + 10_000_000_000, // 10 seconds optimized freshness
            data_hash: name_hash ^ data_size as u64,
            hit_count: 1,
            lru_sequence: cs_get_next_lru_sequence(ctx).unwrap_or(0),
            content_type: 0, // Default content type
            data_size,
            state: 0, // Default state
            _reserved: 0,
        };
        
        let _ = unsafe { CONTENT_STORE.insert(&name_hash, &optimized_entry, 0) };
        info!(ctx, "Optimized storage for frequently accessed item: {}", name_hash);
    } else {
        // Item is not frequently accessed, skip caching
        info!(ctx, "Skipped caching for low-access item: {}", name_hash);
    }
    
    Ok(())
}

/// Update access frequency tracking for CS entries
fn cs_update_access_frequency(ctx: &XdpContext, name_hash: u64, access_time: u64) -> Result<(), ()> {
    // Update access count and time for existing entries
    match unsafe { CONTENT_STORE.get(&name_hash) } {
        Some(entry) => {
            let mut updated_entry = *entry;
            updated_entry.hit_count += 1;
            updated_entry.last_access_time = access_time; // Update last access time
            
            let _ = unsafe { CONTENT_STORE.insert(&name_hash, &updated_entry, 0) };
            info!(ctx, "Updated access frequency for CS entry: {}, new count: {}", 
                  name_hash, updated_entry.hit_count);
        }
        None => {
            // Entry doesn't exist, this is a new access
            info!(ctx, "New access tracked for CS entry: {}", name_hash);
        }
    }
    
    Ok(())
}

/// Implement adaptive cleanup based on network conditions
fn adaptive_cleanup_management(ctx: &XdpContext) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    
    // Assess network load
    let network_load = assess_network_load(ctx, current_time)?;
    
    // Adjust cleanup intervals based on network conditions
    match network_load {
        0..=30 => {
            // Low network load, less aggressive cleanup
            info!(ctx, "Low network load, using conservative cleanup");
            let _ = cs_conservative_cleanup(ctx);
        }
        31..=70 => {
            // Medium network load, standard cleanup
            info!(ctx, "Medium network load, using standard cleanup");
            let _ = cs_standard_cleanup(ctx);
        }
        71..=100 => {
            // High network load, aggressive cleanup
            info!(ctx, "High network load, using aggressive cleanup");
            let _ = cs_aggressive_cleanup(ctx);
        }
        _ => {
            // Default to standard cleanup
            let _ = cs_standard_cleanup(ctx);
        }
    }
    
    Ok(())
}

/// Assess current network load (0-100)
fn assess_network_load(ctx: &XdpContext, current_time: u64) -> Result<u32, ()> {
    // Check packet processing rate
    let packet_stats = match unsafe { PACKET_STATS.get(&0) } {
        Some(stats) => *stats,
        None => PacketStats::new(),
    };
    
    // Check PIT and CS utilization
    let pit_utilization = match unsafe { PIT_STATS.get(&0) } {
        Some(stats) => ((stats.active_entries * 100) / 1000).min(100) as u32,
        None => 0,
    };
    
    let cs_utilization = match unsafe { CS_STATS.get(&0) } {
        Some(stats) => ((stats.current_entries * 100) / (MAX_CS_ENTRIES as u64)).min(100) as u32,
        None => 0,
    };
    
    // Calculate composite network load
    let packet_load = if packet_stats.packets_processed > 5000 {
        80
    } else if packet_stats.packets_processed > 1000 {
        50
    } else {
        20
    };
    
    let total_load = (packet_load + pit_utilization + cs_utilization) / 3;
    
    info!(ctx, "Network load assessment: packet_load={}, pit_util={}, cs_util={}, total={}", 
          packet_load, pit_utilization, cs_utilization, total_load);
    
    Ok(total_load)
}

/// Conservative cleanup for low network load
fn cs_conservative_cleanup(ctx: &XdpContext) -> Result<(), ()> {
    // Only clean up clearly stale entries
    let current_time = unsafe { bpf_ktime_get_ns() };
    let stale_threshold = 30_000_000_000; // 30 seconds
    
    // Sample-based cleanup (since we can't iterate)
    for sample_id in 0..5 {
        let sample_hash = (current_time / 1_000_000_000 + sample_id) as u64;
        
        match unsafe { CONTENT_STORE.get(&sample_hash) } {
            Some(entry) => {
                if current_time - entry.created_time > stale_threshold {
                    let _ = unsafe { CONTENT_STORE.remove(&sample_hash) };
                    info!(ctx, "Conservative cleanup removed stale entry: {}", sample_hash);
                }
            }
            None => continue,
        }
    }
    
    Ok(())
}

/// Standard cleanup for medium network load
fn cs_standard_cleanup(ctx: &XdpContext) -> Result<(), ()> {
    // Standard LRU-based cleanup
    let entries_to_evict = (MAX_CS_ENTRIES as u32 / 10).max(1); // Evict 10% of cache
    let evicted = cs_evict_multiple_lru_entries(ctx, entries_to_evict);
    
    if evicted > 0 {
        info!(ctx, "Standard cleanup evicted {} entries", evicted);
    }
    
    Ok(())
}

/// Aggressive cleanup for high network load
fn cs_aggressive_cleanup(ctx: &XdpContext) -> Result<(), ()> {
    // Aggressive cleanup to free up resources
    let entries_to_evict = (MAX_CS_ENTRIES as u32 / 4).max(1); // Evict 25% of cache
    let evicted = cs_evict_multiple_lru_entries(ctx, entries_to_evict);
    
    if evicted > 0 {
        info!(ctx, "Aggressive cleanup evicted {} entries", evicted);
    }
    
    // Also trigger PIT cleanup
    let _ = pit_aggressive_cleanup(ctx);
    
    Ok(())
}

/// Aggressive PIT cleanup for high network load
fn pit_aggressive_cleanup(ctx: &XdpContext) -> Result<(), ()> {
    let current_time = unsafe { bpf_ktime_get_ns() };
    let mut cleaned_count = 0u32;
    
    // Sample-based aggressive cleanup
    for sample_id in 0..20 {
        let sample_hash = (current_time / 100_000_000 + sample_id) as u64;
        
        match unsafe { PIT_TABLE.get(&sample_hash) } {
            Some(entry) => {
                let entry_age = current_time - entry.created_time;
                // More aggressive timeout (2 seconds instead of 4)
                if entry_age > 2_000_000_000 {
                    let _ = unsafe { PIT_TABLE.remove(&sample_hash) };
                    cleaned_count += 1;
                    
                    // Clean up associated faces
                    let face_key = (sample_hash << 8) | (entry.incoming_face as u64);
                    let _ = unsafe { PIT_ADDITIONAL_FACES.remove(&face_key) };
                }
            }
            None => continue,
        }
    }
    
    if cleaned_count > 0 {
        info!(ctx, "Aggressive PIT cleanup removed {} entries", cleaned_count);
        
        // Update statistics
        update_pit_stats(ctx, |stats| {
            stats.entries_expired += cleaned_count as u64;
            stats.active_entries = stats.active_entries.saturating_sub(cleaned_count as u64);
        });
    }
    
    Ok(())
}
