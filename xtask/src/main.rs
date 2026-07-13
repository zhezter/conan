use conanprotocol::comm::notification::ConanNotif;
use std::error::Error;

// NOTE: This workspace is only for scratchpad codes, testing, trying things out, migrations etc.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let notif = ConanNotif::Text("Steve".to_string(), "Hello this is steve".to_string());
    notif.notify().await?;
    ConanNotif::Sys("This is a system text".to_string())
        .notify()
        .await?;
    Ok(())
}
