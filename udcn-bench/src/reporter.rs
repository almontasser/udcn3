use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};
use crate::benchmarks::BenchmarkResult;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub timestamp: String,
    pub results: HashMap<String, BenchmarkResult>,
    pub summary: BenchmarkSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_operations: u64,
    pub average_throughput: f64,
    pub average_latency: f64,
    pub total_duration: f64,
}

pub struct Reporter {
    results: HashMap<String, BenchmarkResult>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    pub fn add_result(&mut self, name: &str, result: BenchmarkResult) {
        self.results.insert(name.to_string(), result);
    }

    pub fn save_results(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let summary = self.calculate_summary();
        let report = BenchmarkReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            results: self.results.clone(),
            summary,
        };

        let json = serde_json::to_string_pretty(&report)?;
        fs::write(filename, json)?;
        
        println!("Benchmark results saved to {}", filename);
        Ok(())
    }

    pub fn print_summary(&self) {
        if self.results.is_empty() {
            println!("No benchmark results to display");
            return;
        }

        println!("\n=== Benchmark Summary ===");
        println!("{:<20} {:<15} {:<15} {:<15} {:<15}", "Test", "Operations", "Throughput", "Avg Latency", "Success Rate");
        println!("{}", "-".repeat(80));

        for (name, result) in &self.results {
            println!(
                "{:<20} {:<15} {:<15.2} {:<15.2} {:<15.2}%",
                name,
                result.operations,
                result.throughput,
                result.latency_avg.as_secs_f64() * 1000.0, // Convert to ms
                result.success_rate
            );
        }

        let summary = self.calculate_summary();
        println!("\n=== Overall Summary ===");
        println!("Total Operations: {}", summary.total_operations);
        println!("Average Throughput: {:.2} ops/sec", summary.average_throughput);
        println!("Average Latency: {:.2} ms", summary.average_latency);
        println!("Total Duration: {:.2} seconds", summary.total_duration);
    }

    fn calculate_summary(&self) -> BenchmarkSummary {
        if self.results.is_empty() {
            return BenchmarkSummary {
                total_operations: 0,
                average_throughput: 0.0,
                average_latency: 0.0,
                total_duration: 0.0,
            };
        }

        let total_operations: u64 = self.results.values().map(|r| r.operations).sum();
        let average_throughput: f64 = self.results.values().map(|r| r.throughput).sum::<f64>() / self.results.len() as f64;
        let average_latency: f64 = self.results.values()
            .map(|r| r.latency_avg.as_secs_f64() * 1000.0)
            .sum::<f64>() / self.results.len() as f64;
        let total_duration: f64 = self.results.values()
            .map(|r| r.duration.as_secs_f64())
            .sum::<f64>();

        BenchmarkSummary {
            total_operations,
            average_throughput,
            average_latency,
            total_duration,
        }
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}