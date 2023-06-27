//! Provides functionality relating to Steam TOTP. Based on 
//! <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing 
//! all necessary features.

use std::{io::Cursor, time::{SystemTime, SystemTimeError, UNIX_EPOCH}, fmt};
use hmac::{Hmac, Mac};
use byteorder::{BigEndian, ReadBytesExt};
use sha1::{Sha1, Digest};
use base64::Engine;

const CHARS: &[char] = &['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 
'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y'];

type HmacSha1 = Hmac<Sha1>;

/// Any number of errors that can occur during code generations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The secret could not be encoded to base64.
    #[error("Error decoding secret from base64: {}", .0)]
    InvalidSecret(#[from] base64::DecodeError),
    /// The secret given is empty.
    #[error("The secret is empty.")]
    EmptySecret,
    /// System time is set to before the Unix epoch.
    #[error("SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", .0)]
    SystemTime(#[from] SystemTimeError),
    /// An error occurred when reading/writing bytes from/to a [`Cursor`]. This should reasonably 
    /// never happen, but if it does it will be returned here.
    #[error("IO error: {}", .0)]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy)]
/// The tag used in [`generate_confirmation_key`].
pub enum Tag {
    /// To load the confirmations page.
    Conf,
    /// To load details about a trade.
    Details,
    /// To confirm a confirmation.
    Allow,
    /// To cancel a confirmation.
    Cancel,
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conf => write!(f, "conf"),
            Self::Details => write!(f, "details"),
            Self::Allow => write!(f, "allow"),
            Self::Cancel => write!(f, "cancel"),
        }
    }
}

/// Generates the 5-character authentication code to login to Steam using your `shared_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers. 
/// If present, this will add the offset onto your system's current time. Otherwise no offset is 
/// used.
/// 
/// # Examples
///
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

/// Generates a confirmation key for responding to mobile confirmations using your 
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
///
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
/// 
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
    let decoded = base64::engine::general_purpose::STANDARD.decode(secret)?;
    let mut mac = HmacSha1::new_from_slice(&decoded[..])
        .map_err(|_e| Error::EmptySecret)?;
    
    mac.update(bytes);
    Ok(mac)
}

/// An error occurred during the request.
#[cfg(feature = "reqwest")]
#[derive(thiserror::Error, Debug)]
pub enum RequestError {
    /// A request error occured (either network or deserialization).
    #[error("Reqwest error: {}", .0)]
    Reqwest(#[from] reqwest::Error),
    /// An error occurred when reading your computer's system time.
    #[error("SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", .0)]
    SystemTime(#[from] SystemTimeError),
}

/// Gets how many seconds we are **behind** Steam's servers.
#[cfg(feature = "reqwest")]
pub async fn get_steam_server_time_offset() -> Result<i64, RequestError> {
    use std::str::FromStr;
    use serde::{de, Deserialize, Deserializer};
    
    fn from_string<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
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
    fn gets_device_id() {
        let device_id = get_device_id(76561197960287930);
        
        assert_eq!(device_id, "android:6d3f10d9-6369-a1ae-97a0-94df28b95192");
    }
}