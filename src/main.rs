use std::{error::Error, path::PathBuf, time::Duration};

use clap::Parser;
use rift_rust::{
    lie_exchange::Timer,
    network::{Network, Passivity},
    topology::TopologyDescription,
};
use tracing::info;
use tracing_subscriber::fmt::format;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    /// The topology .yaml file to use.
    topology: PathBuf,
    #[arg(long, conflicts_with("non_passive"))]
    /// Run only passive nodes
    passive: bool,
    #[arg(long, conflicts_with("passive"))]
    /// Run only non-passive nodes
    non_passive: bool,
    #[arg(long, default_value = "info")]
    /// The max tracing level
    max_level: tracing::Level,
    #[arg(long)]
    /// Take a JSON snapshot every N seconds
    snapshot: Option<u64>,
    /// If provided, only run the network for N snapshots and then exit. Otherwise, run forever.
    /// Requires `snapshot` to be passed.
    #[arg(long, requires = "snapshot")]
    max_snapshots: Option<usize>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .event_format(format::format().pretty())
        .with_max_level(args.max_level)
        .without_time()
        .init(); // you are going to loose Subscriber

    let passivity = match (args.passive, args.non_passive) {
        (true, true) => unreachable!("--passive and --non-passive conflict with eachother"),
        (true, false) => Passivity::PassiveOnly,
        (false, true) => Passivity::NonPassiveOnly,
        (false, false) => Passivity::Both,
    };

    std::env::set_var("RUST_BACKTRACE", "1");

    let topology = std::fs::read_to_string(args.topology)?;
    let topology = {
        let mut topology: TopologyDescription = serde_yaml::from_str(&topology)?;
        topology.finalize();
        topology
    };

    let mut network = Network::from_desc(&topology, passivity)?;

    let mut timer = None;
    let mut i = 0;
    if let Some(snapshot_period) = args.snapshot {
        timer = Some(Timer::new(Duration::from_secs(snapshot_period)));
    }
    loop {
        network.step()?;

        if let Some(ref mut timer) = timer {
            if timer.is_expired() {
                let json = serde_json::to_string_pretty(&network)?;
                let path = format!("logs/out_{}.json", i);
                std::fs::write(&path, json)?;
                info!(path = path, "wrote debug serialization");
                timer.start();
                i += 1;
            }
        }

        if let Some(max_snaps) = args.max_snapshots {
            if i == max_snaps {
                break;
            }
        }
    }
    Ok(())
}
