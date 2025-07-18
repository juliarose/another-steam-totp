//! Functions for getting the current time offset from Steam's servers by using the
//! `https://api.steampowered.com/ITwoFactorService/QueryTime/v1/` endpoint.

use std::str::FromStr;
use serde::{de, Deserialize, Deserializer};
use crate::Error;
use crate::current_timestamp;

fn from_string<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: std::fmt::Display,
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?.parse().map_err(de::Error::custom)
}

#[derive(Deserialize)]
struct ResponseBody {
    #[serde(deserialize_with = "from_string")]
    server_time: i64,
}

#[derive(Deserialize)]
struct Response {
    response: ResponseBody,
}

/// Gets how many seconds we are **behind** Steam's servers.
/// 
/// Time-based one-time passwords (TOTPs) rely on the current timestamp to generate codes.
/// If your system time is inaccurate, use this function to determine the difference (offset)
/// between your system time and Steam's server time. You can then apply this offset to
/// [`generate_auth_code`] or [`generate_confirmation_key`].
/// 
/// In most cases, your system time should be close enough that you do not need to use an offset.
/// 
/// # Examples
/// ```no_run
/// use another_steam_totp::get_steam_server_time_offset;
/// 
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let offset = get_steam_server_time_offset().await?;
///     println!("Steam server time offset: {offset} seconds");
///     Ok(())
/// }
/// ```
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub async fn get_steam_server_time_offset() -> Result<i64, Error> {
    let client = reqwest::Client::new();
    let response = client.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v1/")
        .header("content-length", 0)
        .send()
        .await?;
    let json = response.json().await?;
    
    get_offset_from_response(&json)
}

/// Gets how many seconds we are **behind** Steam's servers.
/// 
/// Time-based one-time passwords (TOTPs) rely on the current timestamp to generate codes.
/// If your system time is inaccurate, use this function to determine the difference (offset)
/// between your system time and Steam's server time. You can then apply this offset to
/// [`generate_auth_code`] or [`generate_confirmation_key`].
/// 
/// In most cases, your system time should be close enough that you do not need to use an offset.
/// 
/// # Examples
/// ```no_run
/// use another_steam_totp::get_steam_server_time_offset_sync;
/// 
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let offset = get_steam_server_time_offset_sync()?;
///     println!("Steam server time offset: {offset} seconds");
///     Ok(())
/// }
/// ```
#[cfg(feature = "ureq")]
#[cfg_attr(docsrs, cfg(feature = "ureq"))]
pub fn get_steam_server_time_offset_sync() -> Result<i64, Error> {
    let mut response = ureq::post("https://api.steampowered.com/ITwoFactorService/QueryTime/v1/")
        .header("content-length", 0)
        .send_empty()?;
    let json = response
        .body_mut()
        .read_json()?;
    
    get_offset_from_response(&json)
}

fn get_offset_from_response(response: &Response) -> Result<i64, Error> {
    let current_timestamp = current_timestamp()?;
    let offset = response.response.server_time - current_timestamp as i64;
    
    Ok(offset)
}