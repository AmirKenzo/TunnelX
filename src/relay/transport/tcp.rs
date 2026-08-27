use anyhow::Result;
use tokio::net::TcpStream;

pub async fn dial(addr: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}
