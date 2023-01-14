use std::{error::Error, path::PathBuf};

use clap::Parser;
use rift_rust::{
    network::{Network, Passivity},
    topology::TopologyDescription,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The topology .yaml file to use.
    #[arg(long)]
    topology: PathBuf,
    #[arg(long, conflicts_with("non_passive"))]
    passive: bool,
    #[arg(long, conflicts_with("passive"))]
    non_passive: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");

    let args = Args::parse();
    let passivity = match (args.passive, args.non_passive) {
        (true, true) => unreachable!("--passive and --non-passive conflict with eachother"),
        (true, false) => Passivity::PassiveOnly,
        (false, true) => Passivity::NonPassiveOnly,
        (false, false) => Passivity::Both,
    };

    let topology = std::fs::read_to_string(args.topology)?;
    let topology: TopologyDescription = serde_yaml::from_str(&topology)?;
    println!("{:#?}", topology);

    let mut network = Network::from_desc(&topology, passivity)?;
    network.run()?;
    Ok(())
    // let mut bytes = vec![];
    // stdin()
    //     .read_to_end(&mut bytes)
    //     .expect("Couldn't read stdin!");
    // let mut keystore = SecretKeyStore::new();
    // keystore.add_secret(
    //     NonZeroU32::new(1u32).unwrap(),
    //     Key::Sha256("super secret!".to_string()),
    // );
    // println!("{:?}", parse_security_envelope(&bytes, &keystore));
}
