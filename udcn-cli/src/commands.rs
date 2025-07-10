use clap::ArgMatches;
use log::{info, warn, error};
use std::path::Path;
use std::net::SocketAddr;
use crate::utils::format_bytes;
use crate::daemon_client::DaemonClient;
use crate::node_manager::NodeManager;
use crate::file_transfer::SimpleFileTransfer;

pub async fn handle_node_command(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut node_manager = NodeManager::new(None);
    
    match matches.subcommand() {
        Some(("list", _)) => {
            info!("Listing all nodes");
            let nodes = node_manager.list_nodes();
            
            if nodes.is_empty() {
                println!("No nodes found");
            } else {
                println!("Registered nodes:");
                for node in nodes {
                    println!("  {} - {} ({})", node.id, node.address, node.status);
                }
            }
            Ok(())
        }
        Some(("add", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").unwrap();
            let address = sub_matches.get_one::<String>("address").unwrap();
            info!("Adding node {} at {}", id, address);
            
            match node_manager.add_node(id.clone(), address.clone()) {
                Ok(_) => println!("Node '{}' added successfully", id),
                Err(e) => return Err(format!("Failed to add node: {}", e).into()),
            }
            Ok(())
        }
        Some(("remove", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").unwrap();
            info!("Removing node {}", id);
            
            match node_manager.remove_node(id) {
                Ok(_) => println!("Node '{}' removed successfully", id),
                Err(e) => return Err(format!("Failed to remove node: {}", e).into()),
            }
            Ok(())
        }
        Some(("show", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").unwrap();
            info!("Showing node {}", id);
            
            match node_manager.get_node(id) {
                Some(node) => println!("{}", node),
                None => println!("Node '{}' not found", id),
            }
            Ok(())
        }
        _ => {
            println!("No node subcommand specified. Use --help for usage information.");
            Ok(())
        }
    }
}

pub async fn handle_network_command(
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut node_manager = NodeManager::new(None);
    
    match matches.subcommand() {
        Some(("status", _)) => {
            info!("Showing network status");
            let status = node_manager.get_network_status();
            println!("{}", status.format());
            Ok(())
        }
        Some(("discover", _)) => {
            info!("Discovering network nodes");
            println!("Starting network discovery...");
            
            match node_manager.discover_nodes().await {
                Ok(discovered) => {
                    if discovered.is_empty() {
                        println!("No new nodes discovered");
                    } else {
                        println!("Discovered {} nodes:", discovered.len());
                        for node in discovered {
                            println!("  {} - {}", node.id, node.address);
                        }
                    }
                }
                Err(e) => {
                    error!("Discovery failed: {}", e);
                    println!("Network discovery failed: {}", e);
                }
            }
            Ok(())
        }
        _ => {
            println!("No network subcommand specified. Use --help for usage information.");
            Ok(())
        }
    }
}

pub async fn handle_daemon_command(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = matches.get_one::<String>("config");
    let daemon_client = DaemonClient::new(config_path.map(|s| s.as_str()));
    
    match matches.subcommand() {
        Some(("start", _)) => {
            info!("Starting daemon");
            match daemon_client.start().await {
                Ok(_) => println!("Daemon started successfully"),
                Err(e) => {
                    error!("Failed to start daemon: {}", e);
                    println!("Failed to start daemon: {}", e);
                }
            }
            Ok(())
        }
        Some(("stop", _)) => {
            info!("Stopping daemon");
            match daemon_client.stop().await {
                Ok(_) => println!("Daemon stopped successfully"),
                Err(e) => {
                    error!("Failed to stop daemon: {}", e);
                    println!("Failed to stop daemon: {}", e);
                }
            }
            Ok(())
        }
        Some(("restart", _)) => {
            info!("Restarting daemon");
            match daemon_client.restart().await {
                Ok(_) => println!("Daemon restarted successfully"),
                Err(e) => {
                    error!("Failed to restart daemon: {}", e);
                    println!("Failed to restart daemon: {}", e);
                }
            }
            Ok(())
        }
        Some(("status", _)) => {
            info!("Showing daemon status");
            match daemon_client.status().await {
                Ok(status) => println!("{}", status.format()),
                Err(e) => {
                    error!("Failed to get daemon status: {}", e);
                    println!("Failed to get daemon status: {}", e);
                }
            }
            Ok(())
        }
        _ => {
            println!("No daemon subcommand specified. Use --help for usage information.");
            Ok(())
        }
    }
}

pub async fn handle_send_command(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = matches.get_one::<String>("file").unwrap();
    let ndn_name = matches.get_one::<String>("name").unwrap();
    let chunk_size = matches.get_one::<String>("chunk-size").unwrap().parse::<usize>()?;
    let show_progress = matches.get_flag("progress");
    let target_addr = matches.get_one::<String>("target")
        .map(|s| s.parse::<SocketAddr>())
        .transpose()?
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 6363)));

    info!("Sending file {} with NDN name {} (chunk size: {}) to {}", file_path, ndn_name, chunk_size, target_addr);

    // Validate file exists and is readable
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path).into());
    }
    if !path.is_file() {
        return Err(format!("Path is not a file: {}", file_path).into());
    }

    let file_size = std::fs::metadata(path)?.len();
    info!("File size: {}", format_bytes(file_size));

    if show_progress {
        println!("Sending file: {} ({})", file_path, format_bytes(file_size));
        println!("NDN name: {}", ndn_name);
        println!("Chunk size: {} bytes", chunk_size);
        println!("Target: {}", target_addr);
    }

    // Use the real NDN transport
    match SimpleFileTransfer::send_file_simple(path, ndn_name, chunk_size, target_addr, show_progress).await {
        Ok(_) => {
            println!("File sent successfully");
            info!("File transfer completed successfully");
        }
        Err(e) => {
            error!("File transfer failed: {}", e);
            // Try to provide more specific error information
            if e.to_string().contains("connection refused") {
                eprintln!("Error: Could not connect to target address {}", target_addr);
                eprintln!("Make sure the receiver is running and listening on the correct port");
            } else if e.to_string().contains("timeout") {
                eprintln!("Error: Transfer timed out");
                eprintln!("Try increasing the timeout or check network connectivity");
            } else if e.to_string().contains("No such file") {
                eprintln!("Error: File not found: {}", path.display());
            } else {
                eprintln!("Error: File transfer failed: {}", e);
            }
            return Err(e);
        }
    }

    Ok(())
}

pub async fn handle_receive_command(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let ndn_name = matches.get_one::<String>("name").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let timeout = matches.get_one::<String>("timeout").unwrap().parse::<u64>()?;
    let show_progress = matches.get_flag("progress");
    let source_addr = matches.get_one::<String>("source")
        .map(|s| s.parse::<SocketAddr>())
        .transpose()?
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 6363)));

    info!("Receiving file with NDN name {} to {} (timeout: {}s) from {}", ndn_name, output_path, timeout, source_addr);

    // Validate output directory exists
    let path = Path::new(output_path);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(format!("Output directory does not exist: {}", parent.display()).into());
        }
    }

    if show_progress {
        println!("Receiving file from NDN name: {}", ndn_name);
        println!("Output path: {}", output_path);
        println!("Source: {}", source_addr);
        println!("Timeout: {} seconds", timeout);
    }

    // Use the real NDN transport
    match SimpleFileTransfer::receive_file_simple(ndn_name, output_path, source_addr, timeout, show_progress).await {
        Ok(_) => {
            println!("File received successfully");
            info!("File receive completed successfully");
        }
        Err(e) => {
            error!("File receive failed: {}", e);
            // Try to provide more specific error information
            if e.to_string().contains("connection refused") {
                eprintln!("Error: Could not connect to source address {}", source_addr);
                eprintln!("Make sure the sender is running and accessible");
            } else if e.to_string().contains("timeout") {
                eprintln!("Error: Receive timed out after {} seconds", timeout);
                eprintln!("Try increasing the timeout or check network connectivity");
            } else if e.to_string().contains("No such file") {
                eprintln!("Error: Output path invalid: {}", output_path);
            } else if e.to_string().contains("metadata") {
                eprintln!("Error: Failed to receive file metadata from sender");
                eprintln!("Check that the sender has the requested file: {}", ndn_name);
            } else {
                eprintln!("Error: File receive failed: {}", e);
            }
            return Err(e);
        }
    }

    Ok(())
}
