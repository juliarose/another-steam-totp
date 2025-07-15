//! Errors.

use std::time::SystemTimeError;
use std::fmt;

/// Any number of errors that can occur during code generations.
#[derive(Debug)]
pub enum Error {
    /// The secret could not be decoded from base64.
    InvalidSecret(base64::DecodeError),
    /// The secret given is empty.
    EmptySecret,
    /// System time is set to before the Unix epoch.
    SystemTime(SystemTimeError),
    /// An error occurred when reading/writing bytes. 
    IO(std::io::Error),
    #[cfg(feature = "reqwest")]
    /// An error occurred when making a request.
    Reqwest(reqwest::Error),
    #[cfg(feature = "ureq")]
    /// An error occurred when making a request.
    Ureq(ureq::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret(e) => write!(f, "Error decoding secret from base64: {}", e),
            Self::EmptySecret => write!(f, "The secret is empty."),
            Self::SystemTime(e) => write!(f, "SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "reqwest")]
            Self::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            #[cfg(feature = "ureq")]
            Self::Ureq(e) => write!(f, "Isahc error: {}", e),
        }
    }
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

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

#[cfg(feature = "ureq")]
impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Self::Ureq(e)
    }
}
