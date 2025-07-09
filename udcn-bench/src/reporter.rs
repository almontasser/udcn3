use std::{collections::HashMap, fs};

use serde::{Deserialize, Serialize};

use crate::benchmarks::BenchmarkResult;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub timestamp: String,
    pub results: HashMap<String, BenchmarkResult>,
    pub summary: BenchmarkSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_operations: u64,
    pub average_throughput: f64,
    pub average_latency: f64,
    pub total_duration: f64,
}

use crate::benchmarks::{PerformanceMetrics, RegressionDetector};
use std::time::SystemTime;

/// Enhanced benchmark report with performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedBenchmarkReport {
    pub summary: BenchmarkSummary,
    pub detailed_results: Vec<BenchmarkResult>,
    pub performance_metrics: Vec<PerformanceMetrics>,
    pub regression_analysis: Option<String>,
    pub timestamp: SystemTime,
}

pub struct Reporter {
    results: HashMap<String, BenchmarkResult>,
    performance_metrics: Vec<PerformanceMetrics>,
    regression_detector: Option<RegressionDetector>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            performance_metrics: Vec::new(),
            regression_detector: None,
        }
    }

    pub fn add_result(&mut self, name: &str, result: BenchmarkResult) {
        self.results.insert(name.to_string(), result);
    }

    pub fn add_performance_metrics(&mut self, metrics: Vec<PerformanceMetrics>) {
        self.performance_metrics.extend(metrics);
    }

    pub fn set_regression_detector(&mut self, detector: RegressionDetector) {
        self.regression_detector = Some(detector);
    }

    pub fn add_enhanced_result(&mut self, name: &str, result: BenchmarkResult, metrics: Vec<PerformanceMetrics>) {
        self.results.insert(name.to_string(), result);
        self.performance_metrics.extend(metrics);
    }

    pub fn generate_enhanced_report(&self) -> EnhancedBenchmarkReport {
        let summary = self.calculate_summary();
        let detailed_results: Vec<BenchmarkResult> = self.results.values().cloned().collect();
        
        let regression_analysis = if let Some(detector) = &self.regression_detector {
            Some(detector.generate_report(&detailed_results))
        } else {
            None
        };

        EnhancedBenchmarkReport {
            summary,
            detailed_results,
            performance_metrics: self.performance_metrics.clone(),
            regression_analysis,
            timestamp: SystemTime::now(),
        }
    }

    pub fn save_enhanced_results(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let report = self.generate_enhanced_report();
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(filename, json)?;
        println!("Enhanced benchmark results saved to {}", filename);
        Ok(())
    }

    pub fn print_performance_metrics(&self) {
        if self.performance_metrics.is_empty() {
            println!("No performance metrics to display");
            return;
        }

        println!("\n=== Performance Metrics Summary ===");
        println!(
            "{:<20} {:<12} {:<12} {:<12} {:<12} {:<12}",
            "Metric", "P50 (ms)", "P95 (ms)", "P99 (ms)", "Cache Hit%", "Packet Loss%"
        );
        println!("{}", "-".repeat(96));

        // Calculate averages across all metrics
        let count = self.performance_metrics.len() as f64;
        let avg_p50 = self.performance_metrics.iter()
            .map(|m| m.latency_p50.as_millis() as f64)
            .sum::<f64>() / count;
        let avg_p95 = self.performance_metrics.iter()
            .map(|m| m.latency_p95.as_millis() as f64)
            .sum::<f64>() / count;
        let avg_p99 = self.performance_metrics.iter()
            .map(|m| m.latency_p99.as_millis() as f64)
            .sum::<f64>() / count;
        let avg_cache_hit = self.performance_metrics.iter()
            .map(|m| m.cache_hit_rate)
            .sum::<f64>() / count;
        let avg_packet_loss = self.performance_metrics.iter()
            .map(|m| m.packet_loss_rate)
            .sum::<f64>() / count;

        println!(
            "{:<20} {:<12.2} {:<12.2} {:<12.2} {:<12.2} {:<12.2}",
            "Average", avg_p50, avg_p95, avg_p99, avg_cache_hit, avg_packet_loss
        );

        // Show latest metrics
        if let Some(latest) = self.performance_metrics.last() {
            println!(
                "{:<20} {:<12.2} {:<12.2} {:<12.2} {:<12.2} {:<12.2}",
                "Latest",
                latest.latency_p50.as_millis() as f64,
                latest.latency_p95.as_millis() as f64,
                latest.latency_p99.as_millis() as f64,
                latest.cache_hit_rate,
                latest.packet_loss_rate
            );
        }
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
        println!(
            "{:<20} {:<15} {:<15} {:<15} {:<15}",
            "Test", "Operations", "Throughput", "Avg Latency", "Success Rate"
        );
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
        println!(
            "Average Throughput: {:.2} ops/sec",
            summary.average_throughput
        );
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
        let average_throughput: f64 =
            self.results.values().map(|r| r.throughput).sum::<f64>() / self.results.len() as f64;
        let average_latency: f64 = self
            .results
            .values()
            .map(|r| r.latency_avg.as_secs_f64() * 1000.0)
            .sum::<f64>()
            / self.results.len() as f64;
        let total_duration: f64 = self
            .results
            .values()
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
