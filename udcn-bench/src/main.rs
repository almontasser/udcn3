use clap::{Arg, Command, ArgMatches};
use log::{debug, error, info, warn};
use std::process;
use std::time::{Duration, Instant};

mod benchmarks;
mod reporter;
mod utils;

use benchmarks::*;
use reporter::Reporter;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("udcn-bench")
        .version("0.1.0")
        .about("UDCN Benchmark Suite - Performance testing for UDCN components")
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for benchmark results")
                .default_value("benchmark_results.json")
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_name("SECONDS")
                .help("Duration for each benchmark in seconds")
                .default_value("10")
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("COUNT")
                .help("Number of threads to use")
                .default_value("1")
        )
        .subcommand(
            Command::new("network")
                .about("Network performance benchmarks")
                .subcommand(Command::new("throughput").about("Measure network throughput"))
                .subcommand(Command::new("latency").about("Measure network latency"))
                .subcommand(Command::new("connections").about("Measure connection handling"))
        )
        .subcommand(
            Command::new("transport")
                .about("Transport layer benchmarks")
                .subcommand(Command::new("tcp").about("TCP transport benchmarks"))
                .subcommand(Command::new("udp").about("UDP transport benchmarks"))
                .subcommand(Command::new("unix").about("Unix socket transport benchmarks"))
        )
        .subcommand(
            Command::new("all")
                .about("Run all benchmarks")
        )
        .get_matches();

    if let Err(e) = run_benchmarks(&matches).await {
        error!("Benchmark failed: {}", e);
        process::exit(1);
    }
}

async fn run_benchmarks(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let output_file = matches.get_one::<String>("output").unwrap();
    let duration = matches.get_one::<String>("duration").unwrap().parse::<u64>()?;
    let threads = matches.get_one::<String>("threads").unwrap().parse::<usize>()?;

    info!("Starting benchmarks with {} threads for {} seconds each", threads, duration);

    let mut reporter = Reporter::new();
    let benchmark_duration = Duration::from_secs(duration);

    match matches.subcommand() {
        Some(("network", sub_matches)) => {
            run_network_benchmarks(sub_matches, &mut reporter, benchmark_duration).await?;
        }
        Some(("transport", sub_matches)) => {
            run_transport_benchmarks(sub_matches, &mut reporter, benchmark_duration).await?;
        }
        Some(("all", _)) => {
            run_all_benchmarks(&mut reporter, benchmark_duration).await?;
        }
        _ => {
            println!("No benchmark specified. Use --help for usage information.");
            return Ok(());
        }
    }

    reporter.save_results(output_file)?;
    reporter.print_summary();

    Ok(())
}

async fn run_network_benchmarks(
    matches: &ArgMatches,
    reporter: &mut Reporter,
    duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("throughput", _)) => {
            info!("Running network throughput benchmark");
            let result = run_throughput_benchmark(duration).await?;
            reporter.add_result("network_throughput", result);
        }
        Some(("latency", _)) => {
            info!("Running network latency benchmark");
            let result = run_latency_benchmark(duration).await?;
            reporter.add_result("network_latency", result);
        }
        Some(("connections", _)) => {
            info!("Running connection handling benchmark");
            let result = run_connection_benchmark(duration).await?;
            reporter.add_result("network_connections", result);
        }
        _ => {
            println!("No network benchmark specified. Use --help for usage information.");
        }
    }
    Ok(())
}

async fn run_transport_benchmarks(
    matches: &ArgMatches,
    reporter: &mut Reporter,
    duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("tcp", _)) => {
            info!("Running TCP transport benchmark");
            let result = run_tcp_benchmark(duration).await?;
            reporter.add_result("transport_tcp", result);
        }
        Some(("udp", _)) => {
            info!("Running UDP transport benchmark");
            let result = run_udp_benchmark(duration).await?;
            reporter.add_result("transport_udp", result);
        }
        Some(("unix", _)) => {
            info!("Running Unix socket transport benchmark");
            let result = run_unix_benchmark(duration).await?;
            reporter.add_result("transport_unix", result);
        }
        _ => {
            println!("No transport benchmark specified. Use --help for usage information.");
        }
    }
    Ok(())
}

async fn run_all_benchmarks(
    reporter: &mut Reporter,
    duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Running all benchmarks");
    
    // Network benchmarks
    let throughput_result = run_throughput_benchmark(duration).await?;
    reporter.add_result("network_throughput", throughput_result);
    
    let latency_result = run_latency_benchmark(duration).await?;
    reporter.add_result("network_latency", latency_result);
    
    let connection_result = run_connection_benchmark(duration).await?;
    reporter.add_result("network_connections", connection_result);
    
    // Transport benchmarks
    let tcp_result = run_tcp_benchmark(duration).await?;
    reporter.add_result("transport_tcp", tcp_result);
    
    let udp_result = run_udp_benchmark(duration).await?;
    reporter.add_result("transport_udp", udp_result);
    
    let unix_result = run_unix_benchmark(duration).await?;
    reporter.add_result("transport_unix", unix_result);
    
    Ok(())
}