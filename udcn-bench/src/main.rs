use std::{
    process,
    time::Duration,
};

use clap::{Arg, ArgMatches, Command};
use log::{error, info};

mod benchmarks;
mod traffic_generator;
mod reporter;
mod utils;
mod topology;

use benchmarks::*;
use reporter::Reporter;
use topology::{TopologySimulator, TopologyType};

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
                .default_value("benchmark_results.json"),
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_name("SECONDS")
                .help("Duration for each benchmark in seconds")
                .default_value("10"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("COUNT")
                .help("Number of threads to use")
                .default_value("1"),
        )
        .arg(
            Arg::new("enhanced")
                .short('e')
                .long("enhanced")
                .action(clap::ArgAction::SetTrue)
                .help("Run enhanced benchmarks with performance monitoring"),
        )
        .arg(
            Arg::new("baseline")
                .short('b')
                .long("baseline")
                .value_name("FILE")
                .help("Baseline results file for regression detection"),
        )
        .arg(
            Arg::new("regression-threshold")
                .long("regression-threshold")
                .value_name("PERCENT")
                .help("Threshold for regression detection (default: 5.0)")
                .default_value("5.0"),
        )
        .subcommand(
            Command::new("network")
                .about("Network performance benchmarks")
                .subcommand(Command::new("throughput").about("Measure network throughput"))
                .subcommand(Command::new("latency").about("Measure network latency"))
                .subcommand(Command::new("connections").about("Measure connection handling")),
        )
        .subcommand(
            Command::new("transport")
                .about("Transport layer benchmarks")
                .subcommand(Command::new("tcp").about("TCP transport benchmarks"))
                .subcommand(Command::new("udp").about("UDP transport benchmarks"))
                .subcommand(Command::new("unix").about("Unix socket transport benchmarks")),
        )
        .subcommand(Command::new("all").about("Run all benchmarks"))
        .subcommand(
            Command::new("topology")
                .about("Network topology simulation benchmarks")
                .arg(
                    Arg::new("topology-type")
                        .short('T')
                        .long("topology")
                        .value_name("TYPE")
                        .help("Topology type: linear, tree, mesh, ring, star")
                        .default_value("linear"),
                )
                .arg(
                    Arg::new("nodes")
                        .short('n')
                        .long("nodes")
                        .value_name("COUNT")
                        .help("Number of nodes in topology")
                        .default_value("10"),
                )
                .arg(
                    Arg::new("traffic-pattern")
                        .short('p')
                        .long("pattern")
                        .value_name("PATTERN")
                        .help("Traffic pattern: ndn_interest_data, http_like, high_throughput")
                        .default_value("ndn_interest_data"),
                )
                .arg(
                    Arg::new("branching-factor")
                        .long("branching")
                        .value_name("FACTOR")
                        .help("Branching factor for tree topology")
                        .default_value("3"),
                )
        )
        .get_matches();

    if let Err(e) = run_benchmarks(&matches).await {
        error!("Benchmark failed: {}", e);
        process::exit(1);
    }
}

async fn run_benchmarks(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let output_file = matches.get_one::<String>("output").unwrap();
    let duration = matches
        .get_one::<String>("duration")
        .unwrap()
        .parse::<u64>()?;
    let threads = matches
        .get_one::<String>("threads")
        .unwrap()
        .parse::<usize>()?;
    let enhanced = matches.get_flag("enhanced");
    let baseline_file = matches.get_one::<String>("baseline");
    let regression_threshold = matches
        .get_one::<String>("regression-threshold")
        .unwrap()
        .parse::<f64>()?;

    info!(
        "Starting benchmarks with {} threads for {} seconds each",
        threads, duration
    );

    let mut reporter = Reporter::new();
    let benchmark_duration = Duration::from_secs(duration);

    // Set up regression detection if baseline file is provided
    if let Some(baseline_path) = baseline_file {
        if let Ok(baseline_content) = std::fs::read_to_string(baseline_path) {
            if let Ok(baseline_report) = serde_json::from_str::<reporter::BenchmarkReport>(&baseline_content) {
                let mut detector = RegressionDetector::new(regression_threshold);
                for result in baseline_report.results.values() {
                    detector.add_baseline(result.clone());
                }
                reporter.set_regression_detector(detector);
                info!("Loaded baseline from {} for regression detection", baseline_path);
            }
        }
    }

    if enhanced {
        info!("Running enhanced benchmarks with performance monitoring");
    }

    match matches.subcommand() {
        Some(("network", sub_matches)) => {
            run_network_benchmarks(sub_matches, &mut reporter, benchmark_duration, enhanced).await?;
        }
        Some(("transport", sub_matches)) => {
            run_transport_benchmarks(sub_matches, &mut reporter, benchmark_duration, enhanced).await?;
        }
        Some(("all", _)) => {
            run_all_benchmarks(&mut reporter, benchmark_duration, enhanced).await?;
        }
        Some(("topology", sub_matches)) => {
            run_topology_benchmarks(sub_matches, &mut reporter, benchmark_duration, enhanced).await?;
        }
        _ => {
            println!("No benchmark specified. Use --help for usage information.");
            return Ok(());
        }
    }

    if enhanced {
        reporter.save_enhanced_results(output_file)?;
        reporter.print_performance_metrics();
    } else {
        reporter.save_results(output_file)?;
    }
    reporter.print_summary();

    Ok(())
}

async fn run_network_benchmarks(
    matches: &ArgMatches,
    reporter: &mut Reporter,
    duration: Duration,
    enhanced: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("throughput", _)) => {
            if enhanced {
                info!("Running enhanced network throughput benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "throughput").await?;
                reporter.add_enhanced_result("network_throughput", result, metrics);
            } else {
                info!("Running network throughput benchmark");
                let result = run_throughput_benchmark(duration).await?;
                reporter.add_result("network_throughput", result);
            }
        }
        Some(("latency", _)) => {
            if enhanced {
                info!("Running enhanced network latency benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "latency").await?;
                reporter.add_enhanced_result("network_latency", result, metrics);
            } else {
                info!("Running network latency benchmark");
                let result = run_latency_benchmark(duration).await?;
                reporter.add_result("network_latency", result);
            }
        }
        Some(("connections", _)) => {
            if enhanced {
                info!("Running enhanced connection handling benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "burst").await?;
                reporter.add_enhanced_result("network_connections", result, metrics);
            } else {
                info!("Running connection handling benchmark");
                let result = run_connection_benchmark(duration).await?;
                reporter.add_result("network_connections", result);
            }
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
    enhanced: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("tcp", _)) => {
            if enhanced {
                info!("Running enhanced TCP transport benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "throughput").await?;
                reporter.add_enhanced_result("transport_tcp", result, metrics);
            } else {
                info!("Running TCP transport benchmark");
                let result = run_tcp_benchmark(duration).await?;
                reporter.add_result("transport_tcp", result);
            }
        }
        Some(("udp", _)) => {
            if enhanced {
                info!("Running enhanced UDP transport benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "burst").await?;
                reporter.add_enhanced_result("transport_udp", result, metrics);
            } else {
                info!("Running UDP transport benchmark");
                let result = run_udp_benchmark(duration).await?;
                reporter.add_result("transport_udp", result);
            }
        }
        Some(("unix", _)) => {
            if enhanced {
                info!("Running enhanced Unix socket transport benchmark");
                let (result, metrics) = run_enhanced_benchmark(duration, "latency").await?;
                reporter.add_enhanced_result("transport_unix", result, metrics);
            } else {
                info!("Running Unix socket transport benchmark");
                let result = run_unix_benchmark(duration).await?;
                reporter.add_result("transport_unix", result);
            }
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
    enhanced: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Running all benchmarks");

    if enhanced {
        info!("Running enhanced benchmarks with performance monitoring");
        
        // Network benchmarks
        let (throughput_result, throughput_metrics) = run_enhanced_benchmark(duration, "throughput").await?;
        reporter.add_enhanced_result("network_throughput", throughput_result, throughput_metrics);

        let (latency_result, latency_metrics) = run_enhanced_benchmark(duration, "latency").await?;
        reporter.add_enhanced_result("network_latency", latency_result, latency_metrics);

        let (connection_result, connection_metrics) = run_enhanced_benchmark(duration, "burst").await?;
        reporter.add_enhanced_result("network_connections", connection_result, connection_metrics);

        // Transport benchmarks
        let (tcp_result, tcp_metrics) = run_enhanced_benchmark(duration, "throughput").await?;
        reporter.add_enhanced_result("transport_tcp", tcp_result, tcp_metrics);

        let (udp_result, udp_metrics) = run_enhanced_benchmark(duration, "burst").await?;
        reporter.add_enhanced_result("transport_udp", udp_result, udp_metrics);

        let (unix_result, unix_metrics) = run_enhanced_benchmark(duration, "latency").await?;
        reporter.add_enhanced_result("transport_unix", unix_result, unix_metrics);
    } else {
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
    }

    Ok(())
}

async fn run_topology_benchmarks(
    matches: &ArgMatches,
    reporter: &mut Reporter,
    duration: Duration,
    enhanced: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let topology_type_str = matches.get_one::<String>("topology-type").unwrap();
    let node_count = matches
        .get_one::<String>("nodes")
        .unwrap()
        .parse::<usize>()?;
    let traffic_pattern = matches.get_one::<String>("traffic-pattern").unwrap();
    let branching_factor = matches
        .get_one::<String>("branching-factor")
        .unwrap()
        .parse::<usize>()?;

    // Parse topology type
    let topology_type = match topology_type_str.as_str() {
        "linear" => TopologyType::Linear,
        "tree" => TopologyType::Tree { branching_factor },
        "mesh" => TopologyType::Mesh,
        "ring" => TopologyType::Ring,
        "star" => TopologyType::Star,
        _ => {
            return Err(format!("Unknown topology type: {}", topology_type_str).into());
        }
    };

    info!(
        "Running topology simulation: {} with {} nodes, {} pattern",
        topology_type_str, node_count, traffic_pattern
    );

    // Create and configure topology simulator
    let mut simulator = TopologySimulator::new(topology_type);
    simulator.generate_topology(node_count)?;

    let (nodes, edges) = simulator.get_topology_stats();
    info!("Generated topology with {} nodes and {} edges", nodes, edges);

    // Run traffic simulation
    let simulation_result = simulator
        .simulate_traffic(traffic_pattern, duration, None, None)
        .await?;

    // Convert topology simulation result to benchmark result
    let benchmark_result = BenchmarkResult {
        name: format!("topology_{}_{}_nodes", topology_type_str, node_count),
        duration: simulation_result.duration,
        operations: simulation_result.total_packets_sent,
        throughput: simulation_result.network_wide_throughput,
        latency_avg: simulation_result.network_wide_latency,
        latency_min: simulation_result.network_wide_latency / 2,
        latency_max: simulation_result.network_wide_latency * 2,
        success_rate: simulation_result.packet_delivery_ratio,
    };

    let benchmark_name = format!(
        "topology_{}_{}_nodes_{}",
        topology_type_str, node_count, traffic_pattern
    );

    if enhanced {
        // Create basic performance metrics for enhanced reporting
        let performance_metrics = crate::benchmarks::PerformanceMetrics {
            timestamp: std::time::SystemTime::now(),
            latency_p50: simulation_result.network_wide_latency,
            latency_p95: simulation_result.network_wide_latency * 2,
            latency_p99: simulation_result.network_wide_latency * 3,
            jitter: Duration::from_millis(1),
            packet_loss_rate: (1.0 - simulation_result.packet_delivery_ratio) * 100.0,
            cache_hit_rate: 85.0, // Default value
            memory_usage_bytes: 1024 * 1024 * 50, // 50MB default
            cpu_usage_percent: 15.0, // Default value
            network_utilization_percent: simulation_result.network_wide_throughput / 1000.0 * 100.0,
        };

        reporter.add_enhanced_result(&benchmark_name, benchmark_result, vec![performance_metrics]);
    } else {
        reporter.add_result(&benchmark_name, benchmark_result);
    }

    // Print topology-specific results
    info!("Topology Simulation Results:");
    info!("  Topology: {} ({} nodes, {} edges)", topology_type_str, nodes, edges);
    info!("  Traffic Pattern: {}", traffic_pattern);
    info!("  Duration: {:?}", simulation_result.duration);
    info!("  Packets Sent: {}", simulation_result.total_packets_sent);
    info!("  Packets Received: {}", simulation_result.total_packets_received);
    info!("  Packet Delivery Ratio: {:.2}%", simulation_result.packet_delivery_ratio * 100.0);
    info!("  Average Path Length: {:.2} hops", simulation_result.average_path_length);
    info!("  Network-wide Throughput: {:.2} packets/sec", simulation_result.network_wide_throughput);
    info!("  Network-wide Latency: {:?}", simulation_result.network_wide_latency);

    // Save topology visualization
    let dot_output = simulator.export_topology_dot();
    let dot_filename = format!("topology_{}_{}_nodes.dot", topology_type_str, node_count);
    std::fs::write(&dot_filename, dot_output)?;
    info!("Topology visualization saved to: {}", dot_filename);

    // Save detailed simulation results
    let json_filename = format!("topology_simulation_{}_{}_nodes.json", topology_type_str, node_count);
    let json_output = serde_json::to_string_pretty(&simulation_result)?;
    std::fs::write(&json_filename, json_output)?;
    info!("Detailed simulation results saved to: {}", json_filename);

    Ok(())
}
