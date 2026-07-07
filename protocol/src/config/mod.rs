use std::{env, fs};

use clap::Parser;
use config::{Config, FileFormat};

use crate::constants::{ARTI_KEYSTORE, CACHE_PATH, CONFIG_PATH, DAEMON_SOCKET};

#[derive(Debug, Parser)]
#[command(about, version, long_about = None)]
pub struct ConanArgs {
    /// Config File
    #[arg(short = 'c', long = "config", default_value = None)]
    pub config: Option<String>,

    /// Socket Location
    #[arg(short = 's', long = "sock", default_value =  None)]
    pub socket: Option<String>,

    /// Key Store path
    #[arg(short = 'k', long = "key", default_value = None)]
    pub key: Option<String>,

    /// Cache Storage Path
    #[arg(short = 'C', long = "cache", default_value = None)]
    pub cache: Option<String>,
}

#[derive(Debug)]
pub struct ConanConfig {
    pub socket_path: String,
    pub arti_key_store: String,
    pub cache_path: String,
}

/// Function to decide final config
///
/// # Errors
pub fn parse_config() -> Result<ConanConfig, Box<dyn std::error::Error>> {
    let args = ConanArgs::parse();
    let home_path = env::var("HOME")?;
    let mut default_config_path = home_path.clone();
    default_config_path.push_str(CONFIG_PATH);
    let config_path = if let Some(s) = args.config {
        s
    } else {
        default_config_path
    };
    let config = match Config::builder()
        .add_source(config::File::new(&config_path, FileFormat::Toml))
        .build()
    {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("Config Erorr, {e} Using default.");
            None
        }
    };
    let socket_path = if let Some(s) = args.socket {
        s
    } else if let Some(ref s) = config
        && let Ok(path) = s.get_string("socket-path")
    {
        path
    } else {
        DAEMON_SOCKET.into()
    };
    let arti_key_store = if let Some(s) = args.key {
        s
    } else if let Some(ref s) = config
        && let Ok(path) = s.get_string("key-path")
    {
        path
    } else {
        let mut key_path = home_path.clone();
        key_path.push_str(ARTI_KEYSTORE);
        key_path
    };
    let cache_path = if let Some(c) = args.cache {
        c
    } else if let Some(ref c) = config
        && let Ok(path) = c.get_string("cache-path")
    {
        path
    } else {
        CACHE_PATH.to_string()
    };
    _ = fs::create_dir(&cache_path);
    let res = ConanConfig {
        socket_path,
        arti_key_store,
        cache_path,
    };
    println!("config: {res:#?}");

    Ok(res)
}
