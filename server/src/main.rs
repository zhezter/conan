use bincode::config;
use conan_server::functions::handle_cmd;
use conanprotocol::{
    PeerConnection,
    comm::enums::{IPCCmd, IPCRes, encode},
    config::parse_config,
};
use std::{error::Error, fs};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_config()?;
    let sock_path = config.socket_path.clone();
    let mut sock_dir = sock_path.split('/').collect::<Vec<_>>();
    sock_dir.pop();
    _ = fs::create_dir_all(sock_dir.join(""));
    if let Err(e) = fs::remove_file(&sock_path) {
        println!("fs error: {e}");
    }
    let listener = match UnixListener::bind(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            println!("Unix Error: {e}");
            return Ok(());
        }
    };
    let mut connection = PeerConnection::create(&config.arti_key_store).await?;
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let mut buf = [0u8; 4096];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    let cmd = match bincode::decode_from_slice::<IPCCmd, _>(
                        &buf[..n],
                        config::standard(),
                    ) {
                        Ok(s) => s.0,
                        Err(e) => {
                            let e = IPCRes::Error(e.to_string());
                            let res = encode(e);
                            socket.write_all(&res).await?;
                            continue;
                        }
                    };
                    let res = match handle_cmd(&mut connection, cmd).await {
                        Ok(s) => match s {
                            Some(s) => s,
                            None => IPCRes::Error("No Response Found".to_string()),
                        },
                        Err(e) => IPCRes::Error(format!("Server Error. {e}")),
                    };
                    let res = encode(res);
                    socket.write_all(&res).await?;
                }
                Err(e) => {
                    println!("error in main: {e}");
                }
            }
        }
    }
}
