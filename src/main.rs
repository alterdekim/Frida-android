use std::{fs, net::{Ipv4Addr}, str};
use clap::{App, Arg, ArgMatches};
use env_logger::Builder;
use log::{error, LevelFilter};
use crate::config::{ ServerConfiguration, ClientConfiguration, ObfsProtocol, ServerPeer };
use fast32::base32::RFC4648;

mod config;
mod client;
mod udp;

#[tokio::main]
async fn main() {
    // Initialize the logger with 'info' as the default level
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let matches = App::new("Frida")
        .version("0.1.2")
        .author("alterwain")
        .about("VPN software (android port)")
        .arg(Arg::with_name("config")
            .long("config")
            .required(true)
            .value_name("B32_RAW")
            .help("Configuration file data (base32 encoded)")
            .takes_value(true))
        .arg(Arg::with_name("fd")
            .long("fd")
            .required(true)
            .value_name("INT")
            .help("File descriptor int")
            .takes_value(true))
        .get_matches();

    let cfg_raw = matches.value_of("config").unwrap();

    let config: ClientConfiguration = serde_yaml::from_slice(RFC4648.decode(cfg_raw.as_bytes()).unwrap().as_slice()).expect("Bad client config file structure");

    client::client_mode(config, matches.value_of("fd").unwrap().parse().unwrap()).await;
}