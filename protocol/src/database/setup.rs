use rusqlite::Connection;
use std::error::Error;

/// # Errors
pub fn setup_db(db_path: &str) -> Result<(), Box<dyn Error>> {
    let conn = Connection::open(db_path)?;
    conn.execute("PRAGMA foreign_keys = ON;", ())?;

    // create peers
    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS peer (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        address TEXT CHECK(address LIKE '%.onion' AND LENGTH(address) = 62)
        );
                ",
        (),
    )?;

    // create chats
    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL REFERENCES peer(id),
        receiver_id INTEGER NOT NULL REFERENCES peer(id),
        data TEXT NOT NULL,
        TIME DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
        (),
    )?;

    Ok(())
}
