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
            info!(ctx, "NDN Data packet detected, passing through");
            Ok(xdp_action::XDP_PASS)
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
use udcn_common::{UdcnConfig, PacketStats};

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

// Filtering action constants
const FILTER_ACTION_ALLOW: u32 = 0;
const FILTER_ACTION_DROP: u32 = 1;
const FILTER_ACTION_REDIRECT: u32 = 2;

// Rate limiting constants
const RATE_LIMIT_WINDOW_MS: u64 = 1000; // 1 second window
const DEFAULT_RATE_LIMIT: u32 = 100; // 100 requests per second

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
    
    // Extract name hash for filtering
    if let Ok(name_hash) = extract_interest_name_hash(ctx, interest_content_start) {
        // Apply filtering rules
        match apply_filter_rules(ctx, name_hash, component_count) {
            Ok(action) => {
                update_packet_stats(ctx, true, action == xdp_action::XDP_PASS, 0, 0);
                Ok(action)
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
