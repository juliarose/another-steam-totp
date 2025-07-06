//! Provides functionality relating to Steam TOTP. Based on 
//! <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing 
//! all necessary features.
//! 
//! Enable the `reqwest` feature to enable the `get_steam_server_time_offset` function.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod tag;

pub use error::Error;
#[cfg(feature = "reqwest")]
pub use error::RequestError;
pub use tag::Tag;

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};
use std::fmt::Write;
use hmac::{Hmac, Mac};
use sha1::{Sha1, Digest};
use base64::Engine;

const CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G',
    'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y',
];

type HmacSha1 = Hmac<Sha1>;

/// Generates the 5-character authentication code to login to Steam using your base64-encoded 
/// `shared_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers. 
/// If present, this will add the offset onto your system's current time. Otherwise no offset is 
/// used.
/// 
/// # Examples
/// ```
/// use another_steam_totp::generate_auth_code;
/// 
/// let shared_secret = "000000000000000000000000000=";
/// let time_offset = None;
/// let code = generate_auth_code(shared_secret, time_offset).unwrap();
/// 
/// assert_eq!(code.len(), 5);
/// ```
pub fn generate_auth_code<T>(
    shared_secret: T,
    time_offset: Option<i64>,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let timestamp = current_timestamp()? as i64 + time_offset.unwrap_or(0);
    
    generate_auth_code_for_time(shared_secret, timestamp)
}

/// Generates a confirmation key for responding to mobile confirmations using your base64-encoded 
/// `identity_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers. 
/// If present, this will add the offset onto your system's current time. Otherwise no offset is 
/// used.
/// 
/// This method returns both the confirmation key and the timestamp used to generate the 
/// confirmation key, these are required parameters when sending the request for 
/// `https://steamcommunity.com/mobileconf/mobileconf/ajaxop`.
/// 
/// # Examples
/// ```
/// use another_steam_totp::{generate_confirmation_key, Tag};
/// 
/// let identity_secret = "000000000000000000000000000=";
/// let time_offset = None;
/// let (code, timestamp) = generate_confirmation_key(
///     identity_secret,
///     Tag::Allow,
///     time_offset,
/// ).unwrap();
/// 
/// // pass these to the request parameters ..
/// ```
pub fn generate_confirmation_key<T>(
    identity_secret: T,
    tag: Tag,
    time_offset: Option<i64>,
) -> Result<(String, i64), Error>
where
    T: AsRef<[u8]>,
{
    let timestamp = current_timestamp()? as i64 + time_offset.unwrap_or(0);
    let confirmation_key = generate_confirmation_key_for_time(identity_secret, tag, timestamp)?;
    
    Ok((confirmation_key, timestamp))
}

/// Gets the device ID for a given 64-bit `steamid`.
/// 
/// # Examples
/// ```
/// use another_steam_totp::get_device_id;
/// 
/// let steamid: u64 = 76561197960287930;
/// let device_id = get_device_id(steamid);
/// 
/// assert_eq!(device_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
/// ```
pub fn get_device_id(steamid: u64) -> String {
    let mut hasher = Sha1::new();

    hasher.update(steamid.to_string().as_bytes());
    
    let result = hasher.finalize();
    let hash = result
        .iter()
        .fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        });
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

/// Generates an auth code for the given time.
fn generate_auth_code_for_time<T>(
    shared_secret: T,
    timestamp: i64,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let mut full_code = {
        let bytes = (timestamp / 30).to_be_bytes();
        let hmac = get_hmac_msg(shared_secret, &bytes)?;
        let result = hmac.finalize().into_bytes();
        let slice_start = result[19] & 0x0F;
        let slice_end = slice_start + 4;
        let slice: &[u8] = &result[slice_start as usize..slice_end as usize];
        let full_code_slice: [u8; 4] = slice.try_into()
            // This probably should never fail.
            .map_err(|_e| std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to convert slice to array.",
            ))?;
        let full_code_bytes = u32::from_be_bytes(full_code_slice);
        
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

/// Generates a confirmation key for the given time.
fn generate_confirmation_key_for_time<T>(
    identity_secret: T,
    tag: Tag,
    timestamp: i64,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let timestamp_bytes = timestamp.to_be_bytes();
    let tag_string = tag.to_string();
    let tag_bytes = tag_string.as_bytes();
    let array = [&timestamp_bytes, tag_bytes].concat();
    let hmac = get_hmac_msg(identity_secret, &array)?;
    let code_bytes = hmac.finalize().into_bytes();
    
    Ok(base64::engine::general_purpose::STANDARD.encode(code_bytes))
}

/// Decodes a hex-encoded secret.
fn decode_hex<T>(s: T) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    let len = s.as_ref().len();
    let mut bytes = Vec::with_capacity(len / 2);
    let mut iter = s.as_ref().iter();
    
    while let Some(hi) = iter.next() {
        // Get the next byte in the pair.
        let lo = iter.next().ok_or(Error::InvalidHexSecret)?;
        let hi_val = (*hi as char).to_digit(16).ok_or(Error::InvalidHexSecret)? as u8;
        let lo_val = (*lo as char).to_digit(16).ok_or(Error::InvalidHexSecret)? as u8;
        let byte = (hi_val << 4) | lo_val;
        
        bytes.push(byte);
    }
    
    return Ok(bytes);
}

/// Decodes a secret from either base64 or hex encoding.
fn decode_secret<T>(secret: T) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    let secret = secret.as_ref();
    // Check if the secret is hex-encoded (contains only hex digits and is of even length)
    let is_hex = secret.len() % 2 == 0 &&
        secret.iter().all(|&b| (b as char).is_ascii_hexdigit());
    let decoded = if is_hex {
        // Decode from hex
        decode_hex(secret)?
    } else {
        // Decode from base64
        base64::engine::general_purpose::STANDARD.decode(secret)?
    };
    
    Ok(decoded)
}

/// Generates an hmac message.
fn get_hmac_msg<T>(
    secret: T,
    bytes: &[u8],
) -> Result<HmacSha1, Error>
where
    T: AsRef<[u8]>,
{
    let decoded = decode_secret(secret)?;
    let mut mac = HmacSha1::new_from_slice(&decoded[..])
        .map_err(|_e| Error::EmptySecret)?;
    
    mac.update(bytes);
    Ok(mac)
}

/// Gets how many seconds we are **behind** Steam's servers.
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub async fn get_steam_server_time_offset() -> Result<i64, RequestError> {
    use std::str::FromStr;
    use serde::{de, Deserialize, Deserializer};
    
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
        server_time: u64,
    }
    
    #[derive(Deserialize)]
    struct Response {
        response: ResponseBody,
    }
    
    let client = reqwest::Client::new();
    let response = client.post("https://api.steampowered.com/ITwoFactorService/QueryTime/v1/")
        .header("content-length", 0)
        .send()
        .await?;
    let json = response.json::<Response>().await?;
    let current_timestamp = current_timestamp()?;
    let offset = json.response.server_time as i64 - current_timestamp as i64;
    
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn generates_confirmation_key_for_time() {
        let identity_secret = "000000000000000000000000000=";
        let hash = generate_confirmation_key_for_time(
            identity_secret,
            Tag::Allow,
            1634603498 as i64,
        ).unwrap();
        
        assert_eq!(hash, "9/OyNC3rk7VNsMFklzayOuznImU=");
    }
    
    #[test]
    fn generating_a_code_works() {
        let shared_secret = "000000000000000000000000000=";
        let time: i64 = 1634603498;
        let code = generate_auth_code_for_time(shared_secret, time).unwrap();
        
        assert_eq!(code, "2C5H2");
    }
    
    #[test]
    fn generating_a_code_from_hex_works() {
        // This is the same as `000000000000000000000000000=` (base64)
        let shared_secret = "D34D34D34D34D34D34D34D34D34D34D34D34D34D";
        let time: i64 = 1634603498;
        let code = generate_auth_code_for_time(shared_secret, time).unwrap();

        assert_eq!(code, "2C5H2");
    }
    
    #[test]
    fn gets_device_id() {
        let device_id = get_device_id(76561197960287930);
        
        assert_eq!(device_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
    }
    
    #[test]
    fn decode_hex_works() {
        let hex = "48656c6c6f";
        let decoded = decode_hex(hex).unwrap();
        
        assert_eq!(decoded, b"Hello");
    }
}
