//! Errors.

use std::time::SystemTimeError;
use std::fmt;

/// Any number of errors that can occur during code generations.
#[derive(Debug)]
pub enum Error {
    /// The secret could not be decoded from base64.
    InvalidSecret(base64::DecodeError),
    /// The secret given is not a valid hex string.
    InvalidHexSecret,
    /// The secret given is empty.
    EmptySecret,
    /// System time is set to before the Unix epoch.
    SystemTime(SystemTimeError),
    /// An error occurred when converting an integer.
    TryFromInt(std::num::TryFromIntError),
    /// An error occurred when reading/writing bytes. 
    IO(std::io::Error),
    /// An error occurred when making a request.
    #[cfg(feature = "reqwest")]
    Reqwest(reqwest::Error),
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Self {
        Self::SystemTime(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Self::InvalidSecret(e)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::TryFromInt(e)
    }
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret(e) => write!(f, "Error decoding secret from base64: {}", e),
            Self::InvalidHexSecret => write!(f, "The secret is not a valid hex string."),
            Self::EmptySecret => write!(f, "The secret is empty."),
            Self::SystemTime(e) => write!(f, "SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", e),
            Self::TryFromInt(e) => write!(f, "Error converting integer: {}", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "reqwest")]
            Self::Reqwest(e) => write!(f, "Reqwest error: {}", e),
        }
    }
}
