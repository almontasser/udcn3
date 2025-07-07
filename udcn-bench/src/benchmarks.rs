use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub operations: u64,
    pub throughput: f64,
    pub latency_avg: Duration,
    pub latency_min: Duration,
    pub latency_max: Duration,
    pub success_rate: f64,
}

impl BenchmarkResult {
    pub fn new(name: String) -> Self {
        Self {
            name,
            duration: Duration::from_secs(0),
            operations: 0,
            throughput: 0.0,
            latency_avg: Duration::from_secs(0),
            latency_min: Duration::from_secs(0),
            latency_max: Duration::from_secs(0),
            success_rate: 0.0,
        }
    }
}

pub async fn run_throughput_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate network operation
        tokio::time::sleep(Duration::from_micros(10)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "throughput".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}

pub async fn run_latency_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate network operation with variable latency
        let latency = (operations % 100) as u64;
        tokio::time::sleep(Duration::from_micros(latency + 1)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "latency".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}

pub async fn run_connection_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate connection setup/teardown
        tokio::time::sleep(Duration::from_micros(50)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "connections".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}

pub async fn run_tcp_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate TCP operations
        tokio::time::sleep(Duration::from_micros(20)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "tcp".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}

pub async fn run_udp_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate UDP operations
        tokio::time::sleep(Duration::from_micros(5)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "udp".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}

pub async fn run_unix_benchmark(
    duration: Duration,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut operations = 0u64;
    let mut latencies = Vec::new();

    while start.elapsed() < duration {
        let op_start = Instant::now();

        // Simulate Unix socket operations
        tokio::time::sleep(Duration::from_micros(3)).await;
        operations += 1;

        let op_duration = op_start.elapsed();
        latencies.push(op_duration);
    }

    let total_duration = start.elapsed();
    let throughput = operations as f64 / total_duration.as_secs_f64();

    let latency_avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let latency_min = *latencies.iter().min().unwrap_or(&Duration::from_secs(0));
    let latency_max = *latencies.iter().max().unwrap_or(&Duration::from_secs(0));

    Ok(BenchmarkResult {
        name: "unix".to_string(),
        duration: total_duration,
        operations,
        throughput,
        latency_avg,
        latency_min,
        latency_max,
        success_rate: 100.0,
    })
}
