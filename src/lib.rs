//! Provides functionality relating to Steam TOTP. Based on
//! <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing
//! all necessary features.
//! 
//! Enable the `reqwest` feature to enable the `get_steam_server_time_offset` function.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod tag;
mod decode;

pub use error::Error;
pub use tag::Tag;

use decode::decode_secret;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt::Write;
use hmac::{Hmac, Mac};
use sha1::{Sha1, Digest};
use base64::Engine;

const CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G',
    'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y',
];

type HmacSha1 = Hmac<Sha1>;

/// Generates the 5-character authentication code to login to Steam using your base64-encoded or
/// hex-encoded `shared_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers.
/// In most cases, you can use no offset (0) without issue. Refer to
/// [`get_steam_server_time_offset`] for more details.
/// 
/// # Examples
/// ```
/// use another_steam_totp::generate_auth_code;
/// 
/// let shared_secret = "000000000000000000000000000=";
/// let code = generate_auth_code(shared_secret, 0).unwrap();
/// 
/// assert_eq!(code.len(), 5);
/// ```
pub fn generate_auth_code<T>(
    shared_secret: T,
    time_offset: i64,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let timestamp = current_timestamp()? + time_offset;
    
    generate_auth_code_for_time(shared_secret, timestamp)
}

/// Generates a confirmation key for responding to mobile confirmations using your base64-encoded
/// or hex-encoded `identity_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers.
/// In most cases, you can use no offset (0) without issue. Refer to
/// [`get_steam_server_time_offset`] for more details.
/// 
/// Returns both the confirmation key and the timestamp used to generate the confirmation key,
/// these are required parameters when sending the request for
/// `https://steamcommunity.com/mobileconf/mobileconf/ajaxop`.
/// 
/// # Examples
/// ```
/// use another_steam_totp::{generate_confirmation_key, Tag};
/// 
/// let identity_secret = "000000000000000000000000000=";
/// let (code, timestamp) = generate_confirmation_key(identity_secret, Tag::Allow, 0).unwrap();
/// ```
pub fn generate_confirmation_key<T>(
    identity_secret: T,
    tag: Tag,
    time_offset: i64,
) -> Result<(String, i64), Error>
where
    T: AsRef<[u8]>,
{
    let timestamp = current_timestamp()? + time_offset;
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
fn current_timestamp() -> Result<i64, Error> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // Safely convert the timestamp to i64.
    let timestamp = i64::try_from(timestamp)?;
    
    Ok(timestamp)
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
            .map_err(|_e| std::io::Error::other(
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
/// 
/// If the time on your system is significantly out of sync with Steam's servers the codes 
/// generated by this crate will be incorrect. In most cases your system time should be accurate
/// enough to not need to use an offset, but if you are experiencing issues with codes being
/// rejected, you can use this function to get the offset in seconds that you need to apply to
/// your system time.
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub async fn get_steam_server_time_offset() -> Result<i64, Error> {
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
        server_time: i64,
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
    let offset = json.response.server_time - current_timestamp;
    
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn generates_confirmation_key_for_time() {
        let identity_secret: &'static str = "000000000000000000000000000=";
        let timestamp = 1634603498;
        let hash = generate_confirmation_key_for_time(
            identity_secret,
            Tag::Allow,
            timestamp,
        ).unwrap();
        
        assert_eq!(hash, "9/OyNC3rk7VNsMFklzayOuznImU=");
    }
    
    #[test]
    fn generating_a_code_works() {
        let shared_secret = "000000000000000000000000000=";
        let timestamp = 1634603498;
        let code = generate_auth_code_for_time(shared_secret, timestamp).unwrap();
        
        assert_eq!(code, "2C5H2");
    }
    
    #[test]
    fn generating_a_code_from_hex_works() {
        // This is the same as `000000000000000000000000000=` (base64)
        let shared_secret = "D34D34D34D34D34D34D34D34D34D34D34D34D34D";
        let timestamp = 1634603498;
        let code = generate_auth_code_for_time(shared_secret, timestamp).unwrap();

        assert_eq!(code, "2C5H2");
    }
    
    #[test]
    fn gets_device_id() {
        let device_id = get_device_id(76561197960287930);
        
        assert_eq!(device_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
    }
}
