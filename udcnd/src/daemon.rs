use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::sync::RwLock;

use crate::{config::Config, service::Service};

pub struct Daemon {
    config: Config,
    services: Arc<RwLock<Vec<Box<dyn Service>>>>,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            services: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting UDCN Daemon services");

        // Initialize core services
        udcn_core::init();
        udcn_transport::init();

        // TODO: Initialize and start services based on configuration
        info!("All services started successfully");

        Ok(())
    }

    pub async fn stop(&mut self) {
        info!("Stopping UDCN Daemon services");

        let services = self.services.read().await;
        for service in services.iter() {
            if let Err(e) = service.stop().await {
                error!("Failed to stop service: {}", e);
            }
        }

        info!("All services stopped");
    }

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Reloading configuration");
        // TODO: Implement configuration reload
        Ok(())
    }
}
