use std::io::{stdin, Read};

use rift_rust::packet::parse_security_envelope;

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    let mut bytes = vec![];
    stdin()
        .read_to_end(&mut bytes)
        .expect("Couldn't read stdin!");
    println!("{:?}", parse_security_envelope(&bytes));
}
