use std::{error::Error, str::FromStr};

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::constants::TOR_RELAY_LIST_URL;

#[derive(Serialize, Deserialize, Debug)]
pub struct RelayDetail {
    n: String,
    f: String,
    a: Vec<String>,
    r: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TorResponse {
    pub version: String,
    pub build_revision: String,
    pub relays_published: String,
    pub relays: Vec<RelayDetail>,
    pub bridges_published: String,
    pub bridges: Vec<String>,
}

impl TorResponse {
    /// Responds back with available tor relays
    ///
    /// ```
    /// let relays = TorResponse::get_response()?;
    /// ```
    /// # Errors
    pub async fn get_response() -> Result<TorResponse, Box<dyn Error>> {
        let url = Url::from_str(TOR_RELAY_LIST_URL)?;
        let text = reqwest::get(url).await?.text().await?;
        let response: TorResponse = serde_json::from_str(&text)?;
        Ok(response)
    }
}
