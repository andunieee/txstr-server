use clap::Parser;

#[derive(Parser)]
#[command(name = "server", about = "a whitelisted server")]
struct Args {
    /// address to listen on
    #[arg(long, default_value = "0.0.0.0:22223")]
    listen: std::net::SocketAddr,

    /// directory where events and settings are stored
    #[arg(long, default_value = "./data")]
    data: std::path::PathBuf,

    /// pubkey (hex or npub) allowed to manage the server, can be repeated
    #[arg(long = "admin", required = true, value_parser = parse_pubkey)]
    admins: Vec<ritualistic::PubKey>,

    /// reject notes that link to images
    #[arg(long)]
    no_images: bool,
}

fn parse_pubkey(s: &str) -> Result<ritualistic::PubKey, String> {
    s.parse().map_err(|err| format!("{}", err))
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("failed to listen on {}: {}", args.listen, err);
            std::process::exit(1);
        }
    };
    log::info!(
        "server listening on {}{}",
        args.listen,
        if args.no_images {
            " (images disabled)"
        } else {
            ""
        }
    );

    let options = server::Options {
        data_dir: args.data,
        admins: args.admins,
        no_images: args.no_images,
    };
    tokio::select! {
        result = server::serve(options, listener) => {
            if let Err(err) = result {
                log::error!("{}", err);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
    }
}
