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
        return Ok(xdp_action::XDP_DROP);
    }
    
    let packet_len = data_end - data_start;
    
    // Parse Ethernet header
    let eth_hdr = match parse_ethernet_header(&ctx) {
        Ok(hdr) => hdr,
        Err(_) => {
            info!(&ctx, "Failed to parse Ethernet header");
            return Ok(xdp_action::XDP_DROP);
        }
    };
    
    // Log packet information
    info!(
        &ctx,
        "Packet received: len={}, eth_type=0x{:x}, processing_time={}ns",
        packet_len,
        eth_hdr.ether_type,
        unsafe { bpf_ktime_get_ns() } - start_time
    );
    
    // Process packet based on Ethernet type
    match eth_hdr.ether_type {
        0x0800 => process_ipv4_packet(&ctx, data_start + mem::size_of::<EthernetHeader>()),
        0x86dd => process_ipv6_packet(&ctx, data_start + mem::size_of::<EthernetHeader>()),
        _ => {
            info!(&ctx, "Unsupported Ethernet type: 0x{:x}", eth_hdr.ether_type);
            Ok(xdp_action::XDP_PASS)
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

/// Process IPv4 packets
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
    
    info!(ctx, "IPv4 packet processed successfully");
    Ok(xdp_action::XDP_PASS)
}

/// Process IPv6 packets
fn process_ipv6_packet(ctx: &XdpContext, ip_start: usize) -> Result<u32, u32> {
    let data_end = ctx.data_end();
    
    // Basic IPv6 header validation (40 bytes minimum)
    if ip_start + 40 > data_end {
        info!(ctx, "IPv6 packet too short for header");
        return Ok(xdp_action::XDP_DROP);
    }
    
    let ip_hdr = unsafe { *(ip_start as *const u8) };
    let ip_version = (ip_hdr >> 4) & 0xF;
    
    if ip_version != 6 {
        info!(ctx, "Invalid IPv6 version: {}", ip_version);
        return Ok(xdp_action::XDP_DROP);
    }
    
    info!(ctx, "IPv6 packet processed successfully");
    Ok(xdp_action::XDP_PASS)
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

/// Version information
#[link_section = "version"]
#[no_mangle]
static VERSION: [u8; 8] = *b"0.1.0\0\0\0";
