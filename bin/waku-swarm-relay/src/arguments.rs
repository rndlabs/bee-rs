use waku_bindings::Multiaddr;

#[derive(clap::Parser)]
#[group(skip)]
pub struct Arguments {
    #[clap(flatten)]
    pub logging: logging::LoggingArguments,
    #[clap(long, help = "Private key for relay operations", value_parser = parse_private_key)]
    pub private_key: String,
    #[clap(long, help = "Peer id of the relay to connect to", value_parser = parse_multiaddr)]
    pub peer: Vec<Multiaddr>,
    #[clap(long, help = "enrtree")]
    pub enrtree: Option<String>,
}

// Write a parser to make sure that the private_key is a valid ethereum private key
// https://ethereum.stackexchange.com/questions/39384/how-to-validate-a-private-key
//
pub fn parse_private_key(private_key: &str) -> Result<String, String> {
    // The private key may be prefixed with 0x
    let private_key = private_key.trim_start_matches("0x");
    // The private key must be 32 bytes and a valid hex string
    if private_key.len() != 64 || !hex::decode(private_key).is_ok() {
        return Err(String::from("Invalid private key"));
    }
    Ok(String::from(private_key))
}

pub fn parse_multiaddr(multiaddr: &str) -> Result<Multiaddr, String> {
    multiaddr
        .parse()
        .map_err(|_| String::from("Invalid multiaddr"))
}
