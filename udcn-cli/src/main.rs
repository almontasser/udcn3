use std::process;

use clap::{Arg, ArgMatches, Command};
use log::error;

mod commands;
mod utils;

use commands::*;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("udcn")
        .version("0.1.0")
        .about("UDCN CLI - Userland Defined Compute Network Command Line Interface")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .global(true),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .subcommand(
            Command::new("node")
                .about("Node management commands")
                .subcommand(Command::new("list").about("List all nodes"))
                .subcommand(
                    Command::new("add")
                        .about("Add a new node")
                        .arg(Arg::new("id").required(true).help("Node ID"))
                        .arg(Arg::new("address").required(true).help("Node address")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a node")
                        .arg(Arg::new("id").required(true).help("Node ID")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show node details")
                        .arg(Arg::new("id").required(true).help("Node ID")),
                ),
        )
        .subcommand(
            Command::new("network")
                .about("Network management commands")
                .subcommand(Command::new("status").about("Show network status"))
                .subcommand(Command::new("discover").about("Discover network nodes")),
        )
        .subcommand(
            Command::new("daemon")
                .about("Daemon management commands")
                .subcommand(Command::new("start").about("Start the daemon"))
                .subcommand(Command::new("stop").about("Stop the daemon"))
                .subcommand(Command::new("restart").about("Restart the daemon"))
                .subcommand(Command::new("status").about("Show daemon status")),
        )
        .subcommand(
            Command::new("send")
                .about("Send a file over NDN")
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .value_name("FILE")
                        .help("File to send")
                        .required(true),
                )
                .arg(
                    Arg::new("name")
                        .short('n')
                        .long("name")
                        .value_name("NAME")
                        .help("NDN name for the file")
                        .required(true),
                )
                .arg(
                    Arg::new("chunk-size")
                        .long("chunk-size")
                        .value_name("SIZE")
                        .help("Chunk size in bytes (default: 8192)")
                        .default_value("8192"),
                )
                .arg(
                    Arg::new("progress")
                        .short('p')
                        .long("progress")
                        .help("Show progress bar")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("receive")
                .about("Receive a file over NDN")
                .arg(
                    Arg::new("name")
                        .short('n')
                        .long("name")
                        .value_name("NAME")
                        .help("NDN name of the file to receive")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Output file path")
                        .required(true),
                )
                .arg(
                    Arg::new("progress")
                        .short('p')
                        .long("progress")
                        .help("Show progress bar")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("timeout")
                        .short('t')
                        .long("timeout")
                        .value_name("SECONDS")
                        .help("Timeout in seconds (default: 30)")
                        .default_value("30"),
                ),
        )
        .get_matches();

    if let Err(e) = run_command(&matches).await {
        error!("Command failed: {}", e);
        process::exit(1);
    }
}

async fn run_command(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("node", sub_matches)) => handle_node_command(sub_matches).await,
        Some(("network", sub_matches)) => handle_network_command(sub_matches).await,
        Some(("daemon", sub_matches)) => handle_daemon_command(sub_matches).await,
        Some(("send", sub_matches)) => handle_send_command(sub_matches).await,
        Some(("receive", sub_matches)) => handle_receive_command(sub_matches).await,
        _ => {
            println!("No command specified. Use --help for usage information.");
            Ok(())
        }
    }
}
