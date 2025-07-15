//! Helper methods for decoding secrets into the required format.

use crate::Error;
use base64::Engine;

/// Converts a single byte to its hex value, returning `None` if the byte is not a valid hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes a hex-encoded secret.
fn decode_hex<T: AsRef<[u8]>>(secret: T) -> Option<Vec<u8>> {
    let secret = secret.as_ref();
    let len = secret.len();
    
    if len % 2 != 0 {
        return None; // Hex strings must have an even length.
    }
    
    let mut bytes: Vec<u8> = Vec::with_capacity(len / 2);
    let iter = secret.iter().as_slice();
    
    for i in (0..len).step_by(2) {
        let hi = iter[i];
        let lo = iter[i + 1];
        let hi_val = hex_value(hi)?;
        let lo_val = hex_value(lo)?;
        
        bytes.push((hi_val << 4) | lo_val);
    }
    
    Some(bytes)
}

/// Decodes a secret from either base64 or hex encoding.
pub fn decode_secret<T: AsRef<[u8]>>(secret: T) -> Result<Vec<u8>, Error> {
    // Attempt to decode the secret as hex if it is hex-encoded. This should fail if the secret is
    // base64-encoded.
    let decoded = if let Some(decoded) = decode_hex(&secret) {
        decoded
    } else {
        // Decode from base64
        base64::engine::general_purpose::STANDARD.decode(&secret)?
    };
    
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn decode_hex_works() {
        let hex = "48656c6c6f";
        let decoded = decode_hex(hex).unwrap();
        
        assert_eq!(decoded, b"Hello");
    }
    
    #[test]
    fn hex_value_works() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'A'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'G'), None);
    }
}
