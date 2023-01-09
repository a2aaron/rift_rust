use std::{
    io::{stdin, Read},
    num::NonZeroU32,
};

use rift_rust::packet::{parse_security_envelope, Key, SecretKeyStore};

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    let mut bytes = vec![];
    stdin()
        .read_to_end(&mut bytes)
        .expect("Couldn't read stdin!");
    let mut keystore = SecretKeyStore::new();
    keystore.add_secret(
        NonZeroU32::new(1u32).unwrap(),
        Key::Sha256("super secret!".to_string()),
    );
    println!("{:?}", parse_security_envelope(&bytes, &keystore));
}
