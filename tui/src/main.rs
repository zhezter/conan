use std::error::Error;

use conan::App;
use conanprotocol::comm::enums::{IPCCmd, encode};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut terminal = ratatui::init();
    let mut app = App::create().await?;
    app.manage_terminal(&mut terminal).await?;

    Ok(())
}
