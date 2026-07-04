use conan::App;
use conanprotocol::config::parse_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_config()?;
    let mut terminal = ratatui::init();
    let mut app = App::create(&config.socket_path).await?;
    let userid = config
        .socket_path
        .split('/')
        .next_back()
        .unwrap_or("Unknown User")
        .split('.')
        .next()
        .unwrap();
    app.manage_terminal(&mut terminal, userid).await?;

    Ok(())
}
