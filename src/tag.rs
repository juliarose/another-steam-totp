//! Tags for confirmations.

use std::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
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
