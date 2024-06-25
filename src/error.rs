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
    /// An error occurred when reading/writing bytes. This should reasonably never happen, but if 
    /// it does it will be returned here.
    IO(std::io::Error),
}

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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret(e) => write!(f, "Error decoding secret from base64: {}", e),
            Self::EmptySecret => write!(f, "The secret is empty."),
            Self::SystemTime(e) => write!(f, "SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
        }
    }
}
