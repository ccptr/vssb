use std::fmt;
use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a sandbox couldn't be started (or a description was rejected).
#[derive(Debug)]
pub enum Error {
    /// The sandbox or command description is invalid.
    Config(String),
    /// The kernel or session lacks something the sandbox needs, and
    /// [`Sandbox::strict`](crate::Sandbox::strict) is on.
    Unsupported(String),
    /// A step on the host side failed.
    Io { context: String, source: io::Error },
    /// A step inside the new namespaces failed, before the program ran.
    Setup { step: String, source: io::Error },
    /// The program could not be executed (not found, not executable, …).
    Exec { program: String, source: io::Error },
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Error {
        Error::Io { context: context.into(), source }
    }

    /// The exit code a shell would report for this failure: 127 when the
    /// program wasn't found, 126 when it couldn't be executed, 125 otherwise.
    pub fn shell_code(&self) -> i32 {
        match self {
            Error::Exec { source, .. } if source.kind() == io::ErrorKind::NotFound => 127,
            Error::Exec { .. } => 126,
            _ => 125,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) | Error::Unsupported(m) => f.write_str(m),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Setup { step, source } => write!(f, "sandbox setup: {step}: {source}"),
            Error::Exec { program, source } => write!(f, "{program}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } | Error::Setup { source, .. } | Error::Exec { source, .. } => Some(source),
            _ => None,
        }
    }
}
