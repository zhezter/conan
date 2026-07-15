use conanprotocol::config::parse_config;
use rusqlite::Connection;
use std::error::Error;

// NOTE: This workspace is only for scratchpad codes, testing, trying things out, migrations etc.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let dbpath = parse_config()?;
    let conn = Connection::open(dbpath.db_path)?;
    let chats = conn.execute("DELETE FROM chat WHERE 1 = 1", ())?;
    println!("chats: {:#?}", chats);
    Ok(())
}
