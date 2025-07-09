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
    
    match result {
        Ok(action) => {
            let allowed = action == xdp_action::XDP_PASS;
            update_packet_stats(&ctx, true, allowed, packet_len, processing_time);
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
            info!(ctx, "NDN Interest packet detected, parsing...");
            process_interest_packet(ctx, payload_start)
        }
        NDN_TLV_DATA => {
            info!(ctx, "NDN Data packet detected, processing PIT lookup");
            process_data_packet(ctx, payload_start)
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
            Ok(cs_entry) => {
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
                face_update_stats(ctx, face_id, 1, 0, cs_entry.data_size as u64, 0);
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
fn cs_lookup(ctx: &XdpContext, name_hash: u64) -> Result<ContentStoreEntry, ()> {
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
                    Ok(updated_entry)
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
        Ok(entry) => {
            if entry.data_size == test_data_size {
                info!(ctx, "CS test: lookup successful, data_size matches");
            } else {
                info!(ctx, "CS test: lookup data_size mismatch: {} != {}", 
                      entry.data_size, test_data_size);
                return Err(());
            }
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

/// Version information
#[link_section = "version"]
#[no_mangle]
static VERSION: [u8; 8] = *b"0.1.0\0\0\0";
