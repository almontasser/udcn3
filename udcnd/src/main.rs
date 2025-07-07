use std::process;

use clap::{Arg, Command};
use log::{error, info};
use tokio::signal;

mod config;
mod daemon;
mod service;

use config::Config;
use daemon::Daemon;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("udcnd")
        .version("0.1.0")
        .about("UDCN Daemon - Userland Defined Compute Network Daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/udcn/udcnd.conf"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as daemon")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let daemon_mode = matches.get_flag("daemon");

    info!("Starting UDCN Daemon");
    info!("Config file: {}", config_path);
    info!("Daemon mode: {}", daemon_mode);

    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    let mut daemon = Daemon::new(config);

    if let Err(e) = daemon.start().await {
        error!("Failed to start daemon: {}", e);
        process::exit(1);
    }

    info!("UDCN Daemon started successfully");

    signal::ctrl_c().await.expect("Failed to listen for ctrl+c");

    info!("Shutting down UDCN Daemon");
    daemon.stop().await;
}
