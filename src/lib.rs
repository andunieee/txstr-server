pub mod images;
pub mod server;
pub mod settings;

pub use server::{Options, Server};

/// open the server and serve it on the given listener until it fails
pub async fn serve(
    options: Options,
    listener: tokio::net::TcpListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::open(options)?;
    let internals = std::sync::Arc::new(ritualistic::server::RelayInternals {
        info: server.information().into(),
        custom_relay: Box::new(tokio::sync::Mutex::new(server)),
    });
    ritualistic::server::serve(internals, listener).await?;
    Ok(())
}
