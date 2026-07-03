use conan::App;
use conanprotocol::config::parse_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_config()?;
    let mut terminal = ratatui::init();
    let mut app = App::create(&config.socket_path).await?;
    app.manage_terminal(&mut terminal).await?;

    Ok(())
}
