use aya::maps::HashMap;
use udcn_common::{PacketStats, ContentStoreStats};
use std::time::{Duration, Instant};

/// Statistics manager for UDCN eBPF programs
pub struct StatsManager<'a> {
    stats_map: HashMap<&'a aya::maps::MapData, u32, PacketStats>,
    cs_stats_map: Option<HashMap<&'a aya::maps::MapData, u32, ContentStoreStats>>,
    last_stats: Option<PacketStats>,
    last_cs_stats: Option<ContentStoreStats>,
    last_update: Option<Instant>,
}

impl<'a> StatsManager<'a> {
    /// Create a new statistics manager
    pub fn new(stats_map: HashMap<&'a aya::maps::MapData, u32, PacketStats>) -> Self {
        Self {
            stats_map,
            cs_stats_map: None,
            last_stats: None,
            last_cs_stats: None,
            last_update: None,
        }
    }

    /// Create a new statistics manager with content store statistics
    pub fn with_cs_stats(
        stats_map: HashMap<&'a aya::maps::MapData, u32, PacketStats>,
        cs_stats_map: HashMap<&'a aya::maps::MapData, u32, ContentStoreStats>,
    ) -> Self {
        Self {
            stats_map,
            cs_stats_map: Some(cs_stats_map),
            last_stats: None,
            last_cs_stats: None,
            last_update: None,
        }
    }

    /// Get current statistics from the eBPF map
    pub fn get_current_stats(&mut self) -> Result<PacketStats, Box<dyn std::error::Error>> {
        let stats = match self.stats_map.get(&0, 0) {
            Ok(stats) => stats,
            Err(_) => PacketStats::new(),
        };
        
        self.last_stats = Some(stats);
        self.last_update = Some(Instant::now());
        
        Ok(stats)
    }

    /// Get current Content Store statistics from the eBPF map
    pub fn get_current_cs_stats(&mut self) -> Result<ContentStoreStats, Box<dyn std::error::Error>> {
        if let Some(ref cs_stats_map) = self.cs_stats_map {
            let stats = match cs_stats_map.get(&0, 0) {
                Ok(stats) => stats,
                Err(_) => ContentStoreStats::new(),
            };
            
            self.last_cs_stats = Some(stats);
            self.last_update = Some(Instant::now());
            
            Ok(stats)
        } else {
            Ok(ContentStoreStats::new())
        }
    }

    /// Get statistics formatted as JSON
    pub fn get_stats_json(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let stats = self.get_current_stats()?;
        let json = serde_json::json!({
            "packets_processed": stats.packets_processed,
            "packets_dropped": stats.packets_dropped,
            "packets_passed": stats.packets_passed,
            "packets_redirected": stats.packets_redirected,
            "bytes_processed": stats.bytes_processed,
            "processing_time_ns": stats.processing_time_ns,
            "interest_packets": stats.interest_packets,
            "data_packets": stats.data_packets,
            "nack_packets": stats.nack_packets,
            "control_packets": stats.control_packets,
            "parse_errors": stats.parse_errors,
            "memory_errors": stats.memory_errors,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(json.to_string())
    }

    /// Get Content Store statistics formatted as JSON
    pub fn get_cs_stats_json(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let cs_stats = self.get_current_cs_stats()?;
        let json = serde_json::json!({
            "lookups": cs_stats.lookups,
            "hits": cs_stats.hits,
            "misses": cs_stats.misses,
            "hit_ratio": if cs_stats.lookups > 0 { cs_stats.hits as f64 / cs_stats.lookups as f64 } else { 0.0 },
            "insertions": cs_stats.insertions,
            "evictions": cs_stats.evictions,
            "expirations": cs_stats.expirations,
            "current_entries": cs_stats.current_entries,
            "bytes_stored": cs_stats.bytes_stored,
            "max_entries_reached": cs_stats.max_entries_reached,
            "cleanups": cs_stats.cleanups,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(json.to_string())
    }

    /// Get combined statistics (both packet and content store) formatted as JSON
    pub fn get_combined_stats_json(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let stats = self.get_current_stats()?;
        let cs_stats = self.get_current_cs_stats()?;
        
        let json = serde_json::json!({
            "packet_stats": {
                "packets_processed": stats.packets_processed,
                "packets_dropped": stats.packets_dropped,
                "packets_passed": stats.packets_passed,
                "packets_redirected": stats.packets_redirected,
                "bytes_processed": stats.bytes_processed,
                "processing_time_ns": stats.processing_time_ns,
                "interest_packets": stats.interest_packets,
                "data_packets": stats.data_packets,
                "nack_packets": stats.nack_packets,
                "control_packets": stats.control_packets,
                "parse_errors": stats.parse_errors,
                "memory_errors": stats.memory_errors,
            },
            "content_store_stats": {
                "lookups": cs_stats.lookups,
                "hits": cs_stats.hits,
                "misses": cs_stats.misses,
                "hit_ratio": if cs_stats.lookups > 0 { cs_stats.hits as f64 / cs_stats.lookups as f64 } else { 0.0 },
                "insertions": cs_stats.insertions,
                "evictions": cs_stats.evictions,
                "expirations": cs_stats.expirations,
                "current_entries": cs_stats.current_entries,
                "bytes_stored": cs_stats.bytes_stored,
                "max_entries_reached": cs_stats.max_entries_reached,
                "cleanups": cs_stats.cleanups,
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(json.to_string())
    }

    /// Calculate rates (packets per second, bytes per second) since last update
    pub fn get_rates(&mut self) -> Result<StatsRates, Box<dyn std::error::Error>> {
        let current_stats = self.get_current_stats()?;
        let current_time = Instant::now();
        
        if let (Some(last_stats), Some(last_time)) = (self.last_stats, self.last_update) {
            let time_diff = current_time.duration_since(last_time).as_secs_f64();
            
            if time_diff > 0.0 {
                let packets_per_sec = (current_stats.packets_processed - last_stats.packets_processed) as f64 / time_diff;
                let bytes_per_sec = (current_stats.bytes_processed - last_stats.bytes_processed) as f64 / time_diff;
                let dropped_per_sec = (current_stats.packets_dropped - last_stats.packets_dropped) as f64 / time_diff;
                
                return Ok(StatsRates {
                    packets_per_sec,
                    bytes_per_sec,
                    dropped_per_sec,
                    time_period: time_diff,
                });
            }
        }
        
        Ok(StatsRates {
            packets_per_sec: 0.0,
            bytes_per_sec: 0.0,
            dropped_per_sec: 0.0,
            time_period: 0.0,
        })
    }

    /// Check if the statistics are stale (no updates in the last N seconds)
    pub fn is_stale(&self, threshold: Duration) -> bool {
        if let Some(last_update) = self.last_update {
            Instant::now().duration_since(last_update) > threshold
        } else {
            true
        }
    }

    /// Calculate Content Store rates (lookups per second, hit ratio, etc.) since last update
    pub fn get_cs_rates(&mut self) -> Result<ContentStoreRates, Box<dyn std::error::Error>> {
        let current_cs_stats = self.get_current_cs_stats()?;
        let current_time = Instant::now();
        
        if let (Some(last_cs_stats), Some(last_time)) = (self.last_cs_stats, self.last_update) {
            let time_diff = current_time.duration_since(last_time).as_secs_f64();
            
            if time_diff > 0.0 {
                let lookups_per_sec = (current_cs_stats.lookups - last_cs_stats.lookups) as f64 / time_diff;
                let hits_per_sec = (current_cs_stats.hits - last_cs_stats.hits) as f64 / time_diff;
                let misses_per_sec = (current_cs_stats.misses - last_cs_stats.misses) as f64 / time_diff;
                let insertions_per_sec = (current_cs_stats.insertions - last_cs_stats.insertions) as f64 / time_diff;
                let evictions_per_sec = (current_cs_stats.evictions - last_cs_stats.evictions) as f64 / time_diff;
                let hit_ratio = if current_cs_stats.lookups > 0 { 
                    current_cs_stats.hits as f64 / current_cs_stats.lookups as f64 
                } else { 
                    0.0 
                };
                
                return Ok(ContentStoreRates {
                    lookups_per_sec,
                    hits_per_sec,
                    misses_per_sec,
                    insertions_per_sec,
                    evictions_per_sec,
                    hit_ratio,
                    time_period: time_diff,
                });
            }
        }
        
        let hit_ratio = if current_cs_stats.lookups > 0 { 
            current_cs_stats.hits as f64 / current_cs_stats.lookups as f64 
        } else { 
            0.0 
        };
        
        Ok(ContentStoreRates {
            lookups_per_sec: 0.0,
            hits_per_sec: 0.0,
            misses_per_sec: 0.0,
            insertions_per_sec: 0.0,
            evictions_per_sec: 0.0,
            hit_ratio,
            time_period: 0.0,
        })
    }

    /// Reset statistics counters in the eBPF map
    pub fn reset_stats(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Note: For now, we can't reset the eBPF map from userspace easily
        // This would require a more complex implementation
        self.last_stats = Some(PacketStats::new());
        self.last_cs_stats = Some(ContentStoreStats::new());
        self.last_update = Some(Instant::now());
        Ok(())
    }
}

/// Statistics rates structure
#[derive(Debug, Clone)]
pub struct StatsRates {
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub dropped_per_sec: f64,
    pub time_period: f64,
}

/// Content Store statistics rates structure
#[derive(Debug, Clone)]
pub struct ContentStoreRates {
    pub lookups_per_sec: f64,
    pub hits_per_sec: f64,
    pub misses_per_sec: f64,
    pub insertions_per_sec: f64,
    pub evictions_per_sec: f64,
    pub hit_ratio: f64,
    pub time_period: f64,
}

impl StatsRates {
    /// Format rates as a human-readable string
    pub fn format(&self) -> String {
        format!(
            "Packets/sec: {:.2}, Bytes/sec: {:.2}, Dropped/sec: {:.2} (over {:.2}s)",
            self.packets_per_sec,
            self.bytes_per_sec,
            self.dropped_per_sec,
            self.time_period
        )
    }
}

impl ContentStoreRates {
    /// Format Content Store rates as a human-readable string
    pub fn format(&self) -> String {
        format!(
            "Lookups/sec: {:.2}, Hits/sec: {:.2}, Misses/sec: {:.2}, Hit ratio: {:.2}%, Insertions/sec: {:.2}, Evictions/sec: {:.2} (over {:.2}s)",
            self.lookups_per_sec,
            self.hits_per_sec,
            self.misses_per_sec,
            self.hit_ratio * 100.0,
            self.insertions_per_sec,
            self.evictions_per_sec,
            self.time_period
        )
    }
}