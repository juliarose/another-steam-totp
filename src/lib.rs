//! Provides functionality relating to Steam TOTP. Based on
//! <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing
//! all necessary features.
//! 
//! # Usage
//! ```
//! use another_steam_totp::generate_auth_code;
//! 
//! let shared_secret = "000000000000000000000000000=";
//! let time_offset = None;
//! // Generates the 5-character time-based one-time password using
//! // your shared_secret.
//! let code = generate_auth_code(shared_secret, time_offset).unwrap();
//! 
//! assert_eq!(code.len(), 5);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod tag;
mod decode;

#[cfg(any(feature = "reqwest", feature = "ureq"))]
mod http;

pub use error::Error;
pub use tag::Tag;

#[cfg(feature = "reqwest")]
pub use http::get_steam_server_time_offset;

#[cfg(feature = "ureq")]
pub use http::get_steam_server_time_offset_sync;

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
/// Defaults to `0` if `None` is provided. Refer to [`get_steam_server_time_offset`] for more
/// details.
/// 
/// # Examples
/// ```
/// use another_steam_totp::generate_auth_code;
/// 
/// let shared_secret = "000000000000000000000000000=";
/// let code = generate_auth_code(shared_secret, None).unwrap();
/// ```
pub fn generate_auth_code<T: AsRef<[u8]>>(
    shared_secret: T,
    time_offset: Option<i64>,
) -> Result<String, Error> {
    let timestamp = get_offset_timestamp(time_offset)?;
    
    generate_auth_code_for_time(shared_secret, timestamp)
}

/// Generates a confirmation key for responding to mobile confirmations using your base64-encoded
/// or hex-encoded `identity_secret`.
/// 
/// The `time_offset` is the number of seconds in which your system is **behind** Steam's servers.
/// Defaults to `0` if `None` is provided. Refer to [`get_steam_server_time_offset`] for more
/// details.
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
/// let (code, timestamp) = generate_confirmation_key(identity_secret, Tag::Allow, None).unwrap();
/// ```
pub fn generate_confirmation_key<T: AsRef<[u8]>>(
    identity_secret: T,
    tag: Tag,
    time_offset: Option<i64>,
) -> Result<(String, u64), Error> {
    let timestamp = get_offset_timestamp(time_offset)?;
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
    generate_device_id(steamid, None)
}

/// Gets the device ID for a given 64-bit `steamid` with a salt.
/// 
/// # Examples
/// ```
/// use another_steam_totp::get_device_id_with_salt;
/// 
/// let steamid: u64 = 76561197960287930;
/// let device_id = get_device_id_with_salt(steamid, "my_salt");
/// 
/// assert_eq!(device_id, "android:bf5ccd6c-3baf-53a8-b21d-7c2d8bb1e9bb");
/// ```
pub fn get_device_id_with_salt(steamid: u64, salt: &str) -> String {
    generate_device_id(steamid, Some(salt))
}

/// Gets the device ID for a given 64-bit `steamid` and an optional salt.
fn generate_device_id(steamid: u64, salt: Option<&str>) -> String {
    let mut hasher = Sha1::new();
    
    if let Some(salt) = salt {
        hasher.update(format!("{steamid}{salt}"));
    } else {
        hasher.update(steamid.to_string());
    }
    
    let result = hasher.finalize();
    let hash = result
        .iter()
        .fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        });
    // sourced from https://github.com/saskenuba/SteamHelper-rs/blob/37d890c1491677415562d6e7440fde64bbeef12e/crates/steam-totp/src/lib.rs#L124
    let (p1, rest) = hash.split_at(8);
    let (p2, rest) = rest.split_at(4);
    let (p3, rest) = rest.split_at(4);
    let (p4, rest) = rest.split_at(4);
    let (p5, _) = rest.split_at(12);
    
    format!("android:{p1}-{p2}-{p3}-{p4}-{p5}")
}

/// Gets your computer's current system time as a Unix timestamp.
fn current_timestamp() -> Result<u64, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Generates an auth code for the given time.
fn generate_auth_code_for_time<T: AsRef<[u8]>>(
    shared_secret: T,
    timestamp: u64,
) -> Result<String, Error> {
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
fn generate_confirmation_key_for_time<T: AsRef<[u8]>>(
    identity_secret: T,
    tag: Tag,
    timestamp: u64,
) -> Result<String, Error> {
    let timestamp_bytes = timestamp.to_be_bytes();
    let tag_string = tag.to_string();
    let tag_bytes = tag_string.as_bytes();
    let array = [&timestamp_bytes, tag_bytes].concat();
    let hmac = get_hmac_msg(identity_secret, &array)?;
    let code_bytes = hmac.finalize().into_bytes();
    
    Ok(base64::engine::general_purpose::STANDARD.encode(code_bytes))
}

/// Generates an hmac message.
fn get_hmac_msg<T: AsRef<[u8]>>(
    secret: T,
    bytes: &[u8],
) -> Result<HmacSha1, Error> {
    let decoded = decode_secret(secret)?;
    let mut mac = HmacSha1::new_from_slice(&decoded[..])
        .map_err(|_e| Error::EmptySecret)?;
    
    mac.update(bytes);
    Ok(mac)
}

/// Subtracts a signed integer from an unsigned integer, saturating at bounds.
fn subtract_unsigned_signed(u: u64, i: i64) -> u64 {
    if i >= 0 {
        u.saturating_sub(i as u64)
    } else {
        u.saturating_add((-i) as u64)
    }
}

/// Gets the current timestamp adjusted by the provided time offset.
fn get_offset_timestamp(time_offset: Option<i64>) -> Result<u64, Error> {
    let current_timestamp = current_timestamp()?;
    let time_offset = time_offset.unwrap_or(0);
    let timestamp = subtract_unsigned_signed(
        current_timestamp,
        time_offset,
    );
    
    Ok(timestamp)
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
