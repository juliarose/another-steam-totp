//! Anotha one.

use std::{io::Cursor, time::{SystemTime, SystemTimeError, UNIX_EPOCH}};
use hmac::{Hmac, Mac};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Sha1, Digest};
use base64;

const CHARS: &[char] = &['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 
'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y'];

type HmacSha1 = Hmac<Sha1>;

// Any number of errors that occur during code generations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{}", .0)]
    IO(#[from] std::io::Error),
    #[error("SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", .0)]
    SystemTime(#[from] SystemTimeError),
    #[error("Error decoding from base64 {}", .0)]
    Base64(#[from] base64::DecodeError),
    #[error("Length of Hmac is invalid")]
    HmacInvalidLength,
}

/// Generates the 5-character authentication code to login to Steam. The secret is your 
/// `shared_secret`.
/// 
/// `time_offset` is the number of seconds in which your system is **behind** Steam's servers. If 
/// set, this will add the offset onto your system's current time.
/// 
/// # Examples
///
/// ```
/// use another_steam_totp::generate_auth_code;
/// 
/// let secret = String::from("000000000000000000000000000=");
/// let time_offset = None;
/// let code = generate_auth_code(secret, time_offset).unwrap();
/// 
/// assert_eq!(code.len(), 5);
/// ```
pub fn generate_auth_code(
    shared_secret: String,
    time_offset: Option<i64>,
) -> Result<String, Error> {
    let timestamp = current_timestamp()? as i64 + time_offset.unwrap_or(0);
    
    generate_auth_code_for_time(shared_secret, timestamp)
}

/// Generates a confirmation key.
/// 
/// `time_offset` is the number of seconds in which your system is **behind** Steam's servers. If 
/// set, this will add the offset onto your system's current time.
pub fn generate_confirmation_key(
    identity_secret: String,
    tag: String,
    time_offset: Option<i64>,
) -> Result<String, Error> {
    let timestamp = current_timestamp()? as i64 + time_offset.unwrap_or(0);
    
    generate_confirmation_key_for_time(identity_secret, timestamp, tag)
}

/// Gets the device ID for a given `steamid`.
/// 
/// # Examples
/// 
/// ```
/// use another_steam_totp::get_device_id;
/// 
/// let devide_id = get_device_id(76561197960287930);
///         
/// assert_eq!(devide_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
/// ```
pub fn get_device_id(steamid: u64) -> String {
    let mut hasher = Sha1::new();

    hasher.update(steamid.to_string().as_bytes());
    
    let result = hasher.finalize();
    let hash = result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // taken from https://crates.io/crates/steam-totp
    let (one, rest) = hash.split_at(8);
    let (two, rest) = rest.split_at(4);
    let (three, rest) = rest.split_at(4);
    let (four, rest) = rest.split_at(4);
    let (five, _) = rest.split_at(12);
    
    format!("android:{one}-{two}-{three}-{four}-{five}")
}

/// Gets your computer's current system time as a Unix timestamp.
fn current_timestamp() -> Result<u64, SystemTimeError> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
    
    Ok(timestamp.as_secs())
}

fn generate_auth_code_for_time(
    shared_secret: String,
    timestamp: i64,
) -> Result<String, Error> {
    let mut full_code = {
        let mut buf = Cursor::new(vec![0u8; 8]);
        
        buf.write_i64::<BigEndian>(timestamp / 30)?;
        
        let bytes: &[u8] = buf.get_ref();
        let hmac = get_hmac_msg(shared_secret, bytes)?;
        let result = hmac.finalize().into_bytes();
        let slice_start = result[19] & 0x0F;
        let slice_end = slice_start + 4;
        let slice: &[u8] = &result[slice_start as usize..slice_end as usize];
        let full_code_bytes = Cursor::new(&slice).read_u32::<BigEndian>()?;
        
        full_code_bytes & 0x7FFFFFFF
    };
    let chars_len = CHARS.len() as u32;
    let code = (0..5)
        .map(|_i| {
            let char_code = CHARS[(full_code % chars_len) as usize];
            
            full_code /= chars_len;
            char_code
        })
        .collect::<String>();
    
    Ok(code)
}

fn generate_confirmation_key_for_time(
    identity_secret: String,
    timestamp: i64,
    tag: String,
) -> Result<String, Error> {
    let timestamp_bytes = timestamp.to_be_bytes();
    let tag_bytes = tag.as_bytes();
    let array = [&timestamp_bytes, tag_bytes].concat();
    let hmac = get_hmac_msg(identity_secret, &array)?;
    let code_bytes = hmac.finalize().into_bytes();
    
    Ok(base64::encode(code_bytes))
}

fn get_hmac_msg(
    secret: String,
    bytes: &[u8],
) -> Result<HmacSha1, Error> {
    let decoded = base64::decode(secret)?;
    let mut mac = HmacSha1::new_from_slice(&decoded[..])
        .map_err(|_e| Error::HmacInvalidLength)?;
    
    mac.update(bytes);
    
    Ok(mac)
}

#[cfg(feature = "reqwest")]
#[derive(thiserror::Error, Debug)]
pub enum RequestError {
    #[error("Reqwest error: {}", .0)]
    Reqwest(#[from] reqwest::Error),
    #[error("Error parsing response from Steam: {}", .0)]
    Serde(#[from] serde_json::error::Error),
    #[error("SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", .0)]
    SystemTime(#[from] SystemTimeError),
    #[error("Error converting current system time to a u32: {}", .0)]
    ConvertSystemTimeToU32(#[from] std::num::TryFromIntError),
}

/// Gets how many seconds we are **behind** Steam's servers.
#[cfg(feature = "reqwest")]
pub async fn get_steam_server_time_offset() -> Result<i64, RequestError> {
    use serde::Deserialize;
    
    #[derive(Deserialize, Debug)]
    struct ResponseBody {
        server_time: u64,
    }
    
    #[derive(Deserialize, Debug)]
    struct Response {
        response: ResponseBody,
    }
    
    let client = reqwest::Client::new();
    let response = client.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v1/")
        .header("content-length", 0)
        .send()
        .await?;
    let bytes = response.bytes().await?;
    let body: Response = serde_json::from_slice(&bytes)?;
    let server_time = body.response.server_time;
    let current_timestamp = current_timestamp()?;
    let offset = server_time as i64 - current_timestamp as i64;
    
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn generates_confirmation_hash_for_time() {
        let hash = generate_confirmation_key_for_time(
            "000000000000000000000000000=".into(),
            1634603498 as i64,
            "allow".into(),
        ).unwrap();
        
        assert_eq!(hash, "9/OyNC3rk7VNsMFklzayOuznImU=");
    }
    
    #[test]
    fn generating_a_code_works() {
        let secret = String::from("000000000000000000000000000=");
        let time: i64 = 1634603498;
        let code = generate_auth_code_for_time(secret, time).unwrap();
        
        assert_eq!(code, "2C5H2");
    }
    
    #[test]
    fn gets_device_id() {
        let devide_id = get_device_id(76561197960287930);
        
        assert_eq!(devide_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
    }
}