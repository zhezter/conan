use conanprotocol::{
    comm::enums::{IPCCmd, IPCRes},
    entities::{manager::Manager, master::Master},
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (worker_sender, worker_receiver) = std::sync::mpsc::channel::<IPCCmd>();
    let (msg_sender, msg_receiver) = tokio::sync::broadcast::channel::<IPCRes>(100);
    let mut master = Master::build(None, worker_sender, msg_receiver);
    let mut manager = Manager::create(worker_receiver, msg_sender).await?;
    println!("Master Started, Starting Manager.");
    manager.init_server()?;
    println!("Manager Started. Establishing Message Routes..");
    manager.setup_slave_communication()?;
    println!("Starting Master...");
    master.setup_communication()?;
    println!("All Set.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
