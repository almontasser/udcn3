use async_trait::async_trait;

#[async_trait]
pub trait Service: Send + Sync {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error>>;
    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>>;
    async fn restart(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop().await?;
        self.start().await?;
        Ok(())
    }
    fn name(&self) -> &str;
    fn is_running(&self) -> bool;
}