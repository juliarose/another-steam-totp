//! Errors.

use std::fmt;
use std::time::SystemTimeError;

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

/// An error occurred during the request.
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
#[derive(Debug)]
pub enum RequestError {
    /// A request error occured (either network or deserialization).
    Reqwest(reqwest::Error),
    /// An error occurred when reading your computer's system time.
    SystemTime(SystemTimeError),
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for RequestError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

#[cfg(feature = "reqwest")]
impl From<SystemTimeError> for RequestError {
    fn from(e: SystemTimeError) -> Self {
        Self::SystemTime(e)
    }
}

#[cfg(feature = "reqwest")]
impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            Self::SystemTime(e) => write!(f, "SystemTimeError: {}. System time is set to before the Unix epoch. To fix this, adjust your clock.", e),
        }
    }
}
