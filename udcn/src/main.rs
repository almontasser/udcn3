use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn, info};
use tokio::signal;
use udcn_common::{PacketStats, ContentStoreStats};

mod stats;
use stats::StatsManager;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "5")]
    stats_interval: u64,
}


fn display_statistics(stats: &PacketStats) {
    println!("╭─────────────────────────────────────────────────────────────────────────────────────╮");
    println!("│                                UDCN Statistics                                      │");
    println!("├─────────────────────────────────────────────────────────────────────────────────────┤");
    println!("│ Packets Processed: {:<10} │ Packets Passed: {:<10} │ Packets Dropped: {:<10} │", 
             stats.packets_processed, stats.packets_passed, stats.packets_dropped);
    println!("│ Interest Packets:  {:<10} │ Data Packets:   {:<10} │ NACK Packets:    {:<10} │", 
             stats.interest_packets, stats.data_packets, stats.nack_packets);
    println!("│ Control Packets:   {:<10} │ Parse Errors:   {:<10} │ Memory Errors:   {:<10} │", 
             stats.control_packets, stats.parse_errors, stats.memory_errors);
    println!("│ Bytes Processed:   {:<10} │ Packets Redirected: {:<7} │ Processing Time: {:<10} ns │", 
             stats.bytes_processed, stats.packets_redirected, stats.processing_time_ns);
    println!("╰─────────────────────────────────────────────────────────────────────────────────────╯");
}

fn display_cs_statistics(cs_stats: &ContentStoreStats) {
    let hit_ratio = if cs_stats.lookups > 0 {
        (cs_stats.hits as f64 / cs_stats.lookups as f64) * 100.0
    } else {
        0.0
    };
    
    println!("╭─────────────────────────────────────────────────────────────────────────────────────╮");
    println!("│                           Content Store Statistics                                   │");
    println!("├─────────────────────────────────────────────────────────────────────────────────────┤");
    println!("│ Total Lookups:     {:<10} │ Cache Hits:     {:<10} │ Cache Misses:    {:<10} │", 
             cs_stats.lookups, cs_stats.hits, cs_stats.misses);
    println!("│ Hit Ratio:         {:<7.2}%    │ Insertions:     {:<10} │ Evictions:       {:<10} │", 
             hit_ratio, cs_stats.insertions, cs_stats.evictions);
    println!("│ Expirations:       {:<10} │ Current Entries:{:<10} │ Bytes Stored:    {:<10} │", 
             cs_stats.expirations, cs_stats.current_entries, cs_stats.bytes_stored);
    println!("│ Max Entries Seen:  {:<10} │ Cleanups:       {:<10} │                          │", 
             cs_stats.max_entries_reached, cs_stats.cleanups);
    println!("╰─────────────────────────────────────────────────────────────────────────────────────╯");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/udcn"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let Opt { iface, stats_interval } = opt;
    let program: &mut Xdp = ebpf.program_mut("udcn").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("XDP program attached successfully to interface {}", iface);

    // Get the statistics maps and create manager
    let stats_map: HashMap<_, u32, PacketStats> = ebpf.map("PACKET_STATS").unwrap().try_into()?;
    let cs_stats_map: HashMap<_, u32, ContentStoreStats> = ebpf.map("CS_STATS").unwrap().try_into()?;
    let mut stats_manager = StatsManager::with_cs_stats(stats_map, cs_stats_map);
    
    println!("UDCN XDP program is running. Press Ctrl-C to stop.");
    println!("Statistics will be displayed every {} seconds.\n", stats_interval);
    
    // Statistics collection loop
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(stats_interval));
    let mut ctrl_c = Box::pin(signal::ctrl_c());
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                match stats_manager.get_current_stats() {
                    Ok(stats) => {
                        display_statistics(&stats);
                        
                        // Also display rates
                        if let Ok(rates) = stats_manager.get_rates() {
                            println!("Rates: {}", rates.format());
                        }
                        
                        // Display Content Store statistics
                        match stats_manager.get_current_cs_stats() {
                            Ok(cs_stats) => {
                                display_cs_statistics(&cs_stats);
                                
                                // Also display CS rates
                                if let Ok(cs_rates) = stats_manager.get_cs_rates() {
                                    println!("CS Rates: {}", cs_rates.format());
                                }
                            }
                            Err(e) => {
                                warn!("Failed to get Content Store statistics: {}", e);
                                display_cs_statistics(&ContentStoreStats::new());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get statistics: {}", e);
                        display_statistics(&PacketStats::new());
                        display_cs_statistics(&ContentStoreStats::new());
                    }
                }
            }
            _ = &mut ctrl_c => {
                println!("Received Ctrl-C, shutting down...");
                break;
            }
        }
    }

    // Display final statistics
    match stats_manager.get_current_stats() {
        Ok(stats) => {
            println!("\nFinal Statistics:");
            display_statistics(&stats);
            
            // Display final Content Store statistics
            match stats_manager.get_current_cs_stats() {
                Ok(cs_stats) => {
                    display_cs_statistics(&cs_stats);
                }
                Err(e) => {
                    warn!("Failed to get final Content Store statistics: {}", e);
                    display_cs_statistics(&ContentStoreStats::new());
                }
            }
            
            // Export final statistics as JSON
            if let Ok(json) = stats_manager.get_combined_stats_json() {
                println!("\nCombined Statistics JSON:");
                println!("{}", json);
            }
        }
        Err(e) => {
            println!("\nFailed to get final statistics: {}", e);
            display_statistics(&PacketStats::new());
            display_cs_statistics(&ContentStoreStats::new());
        }
    }

    Ok(())
}
