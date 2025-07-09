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
    match try_udcn(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Main packet processing logic
fn try_udcn(ctx: XdpContext) -> Result<u32, u32> {
    let start_time = unsafe { bpf_ktime_get_ns() };
    
    // Get packet data bounds
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    
    // Basic packet length validation
    if data_start >= data_end {
        info!(&ctx, "Invalid packet: data_start >= data_end");
        let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
        update_packet_stats(&ctx, false, false, 0, processing_time);
        return Ok(xdp_action::XDP_DROP);
    }
    
    let packet_len = (data_end - data_start) as u64;
    
    // Parse Ethernet header
    let eth_hdr = match parse_ethernet_header(&ctx) {
        Ok(hdr) => hdr,
        Err(_) => {
            info!(&ctx, "Failed to parse Ethernet header");
            let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
            update_packet_stats(&ctx, false, false, packet_len, processing_time);
            return Ok(xdp_action::XDP_DROP);
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
    
    match result {
        Ok(action) => {
            let allowed = action == xdp_action::XDP_PASS;
            update_packet_stats(&ctx, true, allowed, packet_len, processing_time);
            Ok(action)
        }
        Err(e) => {
            update_packet_stats(&ctx, false, false, packet_len, processing_time);
            Err(e)
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
                  PIT_STATE_ACTIVE, PIT_STATE_SATISFIED, PIT_STATE_EXPIRED, 
                  PIT_ENTRY_TIMEOUT_NS, MAX_PIT_ENTRIES, MAX_ADDITIONAL_FACES};

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

/// Process NDN Data packet and check PIT for satisfied Interests
fn process_data_packet(ctx: &XdpContext, data_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Data packet
    let (data_length, tlv_header_size) = match parse_tlv_length(ctx, data_start + 1) {
        Ok(result) => result,
        Err(_) => {
            info!(ctx, "Failed to parse Data TLV length");
            return Ok(xdp_action::XDP_DROP);
        }
    };
    
    // Validate Data packet bounds
    if data_start + tlv_header_size + data_length > data_end {
        info!(ctx, "Data packet truncated, declared length: {}", data_length);
        return Ok(xdp_action::XDP_DROP);
    }
    
    let data_content_start = data_start + tlv_header_size;
    info!(ctx, "Data packet: length={}, content_start={}", data_length, data_content_start);
    
    // Extract name hash from Data packet (first element should be Name TLV)
    if let Ok(name_hash) = extract_interest_name_hash(ctx, data_content_start) {
        // Check if there's a corresponding PIT entry
        match pit_remove(ctx, name_hash) {
            Ok(pit_entry) => {
                info!(ctx, "PIT entry satisfied by Data packet, forwarding to {} faces", 
                      pit_entry.additional_faces_count + 1);
                
                // Forward to primary face
                if let Ok(face_info) = face_get_forwarding_info(ctx, pit_entry.incoming_face) {
                    face_update_stats(ctx, pit_entry.incoming_face, 1, 0, data_length as u64, 0);
                    info!(ctx, "Forwarding Data to primary face: {}", pit_entry.incoming_face);
                } else {
                    info!(ctx, "Primary face {} is unavailable", pit_entry.incoming_face);
                }
                
                // Forward to additional faces (if any)
                for i in 0..pit_entry.additional_faces_count {
                    let face_key = (name_hash << 8) | (i as u64);
                    if let Some(face_entry) = unsafe { PIT_ADDITIONAL_FACES.get(&face_key) } {
                        if let Ok(_face_info) = face_get_forwarding_info(ctx, face_entry.face_id) {
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
                info!(ctx, "No PIT entry found for Data packet, dropping");
                Ok(xdp_action::XDP_DROP)
            }
        }
    } else {
        info!(ctx, "Failed to extract name from Data packet");
        Ok(xdp_action::XDP_DROP)
    }
}

/// Process NDN Interest packet and apply filtering rules
fn process_interest_packet(ctx: &XdpContext, interest_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Parse TLV length for Interest packet
    let (interest_length, tlv_header_size) = match parse_tlv_length(ctx, interest_start + 1) {
        Ok(result) => result,
        Err(_) => {
            info!(ctx, "Failed to parse Interest TLV length");
            update_packet_stats(ctx, false, false, 0, 0);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    
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
    
    // Extract name hash for filtering and PIT operations
    if let Ok(name_hash) = extract_interest_name_hash(ctx, interest_content_start) {
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
fn extract_interest_name_hash(ctx: &XdpContext, name_start: usize) -> Result<u64, ()> {
    let data_end = ctx.data_end();
    
    // Check if we have enough data for Name TLV header
    if name_start + 2 > data_end {
        return Err(());
    }
    
    // Verify this is a Name TLV
    let name_type = unsafe { *(name_start as *const u8) };
    if name_type != NDN_TLV_NAME {
        return Err(());
    }
    
    // Parse name length
    let (name_length, name_header_size) = match parse_tlv_length(ctx, name_start + 1) {
        Ok(result) => result,
        Err(_) => return Err(()),
    };
    
    // Validate name bounds
    if name_start + name_header_size + name_length > data_end {
        return Err(());
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
    
    Ok(hash)
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
fn parse_tlv_length(ctx: &XdpContext, length_start: usize) -> Result<(usize, usize), ()> {
    let data_end = ctx.data_end();
    
    if length_start >= data_end {
        return Err(());
    }
    
    let first_byte = unsafe { *(length_start as *const u8) };
    
    // Single byte length (0-252)
    if first_byte <= 252 {
        return Ok((first_byte as usize, 2)); // 1 byte type + 1 byte length
    }
    
    // Multi-byte length encoding
    match first_byte {
        253 => {
            // 2-byte length
            if length_start + 2 >= data_end {
                return Err(());
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u16;
                u16::from_be(*ptr) as usize
            };
            Ok((length, 4)) // 1 byte type + 1 byte prefix + 2 byte length
        }
        254 => {
            // 4-byte length
            if length_start + 4 >= data_end {
                return Err(());
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u32;
                u32::from_be(*ptr) as usize
            };
            Ok((length, 6)) // 1 byte type + 1 byte prefix + 4 byte length
        }
        255 => {
            // 8-byte length (not commonly used in practice)
            if length_start + 8 >= data_end {
                return Err(());
            }
            let length = unsafe {
                let ptr = (length_start + 1) as *const u64;
                u64::from_be(*ptr) as usize
            };
            Ok((length, 10)) // 1 byte type + 1 byte prefix + 8 byte length
        }
        _ => Err(()),
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
    let (name_length, name_header_size) = match parse_tlv_length(ctx, name_start + 1) {
        Ok(result) => result,
        Err(_) => {
            info!(ctx, "Failed to parse Name TLV length");
            return Err(());
        }
    };
    
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
        let (component_length, component_header_size) = match parse_tlv_length(ctx, current_pos + 1) {
            Ok(result) => result,
            Err(_) => break,
        };
        
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
    let (name_length, name_header_size) = match parse_tlv_length(ctx, current_pos + 1) {
        Ok(result) => result,
        Err(_) => return Err(()),
    };
    
    current_pos += name_header_size + name_length;
    
    // Look for Nonce TLV (type 0x0A)
    while current_pos + 2 < data_end {
        let tlv_type = unsafe { *(current_pos as *const u8) };
        
        if tlv_type == 0x0A { // NDN_TLV_NONCE
            // Parse nonce length
            let (nonce_length, nonce_header_size) = match parse_tlv_length(ctx, current_pos + 1) {
                Ok(result) => result,
                Err(_) => return Err(()),
            };
            
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
        let (tlv_length, tlv_header_size) = match parse_tlv_length(ctx, current_pos + 1) {
            Ok(result) => result,
            Err(_) => break,
        };
        
        current_pos += tlv_header_size + tlv_length;
    }
    
    // No nonce found, generate a simple one based on name hash
    let name_hash = extract_interest_name_hash(ctx, interest_content_start).unwrap_or(0);
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
fn face_get_forwarding_info(ctx: &XdpContext, face_id: u32) -> Result<FaceInfo, ()> {
    match unsafe { FACE_TABLE.get(&face_id) } {
        Some(face_info) => {
            // Check if face is still active
            if face_info.state & 0x01 != 0 { // FACE_STATE_UP
                Ok(*face_info)
            } else {
                info!(ctx, "Face {} is down", face_id);
                Err(())
            }
        }
        None => {
            info!(ctx, "Face {} not found", face_id);
            Err(())
        }
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

/// Version information
#[link_section = "version"]
#[no_mangle]
static VERSION: [u8; 8] = *b"0.1.0\0\0\0";
