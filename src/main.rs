use clap::{CommandFactory, Parser};
use cloudgrepper::cli::{normalize_args, Cli};

fn init_logging(debug: bool) {
    // Python: WARNING by default, DEBUG with -d, all to stderr
    let level = if debug { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        // Python: no args -> help on stderr, exit 1
        eprintln!("{}", Cli::command().render_help());
        std::process::exit(1);
    }
    let cli = Cli::parse_from(normalize_args(args));
    init_logging(cli.debug);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(cloudgrepper::runner::run(cli)) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
