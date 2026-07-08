use std::error::Error;

use chrono::{DateTime, Utc};

use crate::database::DBConnection;

pub struct Chat {
    pub id: u32,
    pub sender_id: u32,
    pub receiver_id: u32,
    pub data: String,
    pub time: DateTime<Utc>,
}

impl Chat {
    /// Used to build Chat Struct with given parameters
    #[must_use]
    pub fn build(text: String, sender: u32, receiver: u32) -> Self {
        let time = Utc::now();
        Self {
            // we're not really adding the id, thats done by sql itself
            id: 0,
            sender_id: sender,
            receiver_id: receiver,
            data: text,
            time,
        }
    }
}

pub trait ChatData {
    /// Lists Chats from Local Database
    /// # Errors
    fn list_all_chat(&self) -> Result<Vec<Chat>, Box<dyn Error>>;
    /// Inserts Chat to Local Database
    /// # Errors
    fn insert_chat(&self, chat: Chat) -> Result<(), Box<dyn Error>>;
    /// Deletes from Local Database based on chat id
    /// # Errors
    fn delete_chat(&self, idx: u32) -> Result<(), Box<dyn Error>>;
}

impl ChatData for DBConnection {
    fn list_all_chat(&self) -> Result<Vec<Chat>, Box<dyn std::error::Error>> {
        let mut result = vec![];
        let mut query = self.connection.prepare("SELECT * FROM chat")?;
        let rows = query.query_map([], |c| {
            let time: String = c.get(4)?;
            let time = DateTime::parse_from_str(&time, "YYYY-MM-DD HH:MM:SS")
                .unwrap()
                .to_utc();
            Ok(Chat {
                id: c.get(0)?,
                sender_id: c.get(1)?,
                receiver_id: c.get(2)?,
                data: c.get(3)?,
                time,
            })
        })?;
        for r in rows {
            let r = r?;
            result.push(r);
        }
        Ok(result)
    }

    fn insert_chat(&self, chat: Chat) -> Result<(), Box<dyn Error>> {
        let mut stmt = self
            .connection
            .prepare("INSERT INTO chat (receiver_id, sender_id, data) VALUES (?1, ?2, ?3)")?;
        match stmt.execute((chat.receiver_id, chat.sender_id, chat.data)) {
            Ok(s) => {
                if s == 0 {
                    return Err("Nothing was inserted.".into());
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn delete_chat(&self, id: u32) -> Result<(), Box<dyn Error>> {
        let mut stmt = self.connection.prepare("DELETE FROM chat WHERE id = ?1")?;
        match stmt.execute([id]) {
            Ok(s) => {
                if s == 0 {
                    return Err("Nothing was inserted.".into());
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}
