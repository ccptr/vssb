//! vssb: a rootless Linux sandbox you can embed in another program.
//!
//! A [`Sandbox`] describes the environment (filesystem view, network,
//! syscall filter, ids, resource limits); a [`Command`] describes one
//! program to run in it. [`Sandbox::spawn`] starts it and returns a
//! [`Child`] handle, much like `std::process`:
//!
//! ```no_run
//! use vssb::{Command, Mount, Sandbox, Stdio};
//!
//! let mut sb = Sandbox::new();
//! sb.system(true).mount(Mount::rw("/home/me/project"));
//! let mut cmd = Command::new("make");
//! cmd.arg("test").cwd("/home/me/project").env("PATH", "/usr/bin:/bin").stdout(Stdio::Piped);
//! let mut child = sb.spawn(cmd)?;
//! let status = child.wait()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Unlike a CLI, the library takes over no process-wide state: it can be
//! called from any thread of a multi-threaded host, starts no threads,
//! installs no signal handlers, doesn't re-execute the host, and its
//! children can't be reaped by the host's `waitpid(-1)`. See README.md
//! for the guarantees and how they are kept.

// libc's rlimit and flag types differ between glibc and musl.
#![allow(clippy::unnecessary_cast)]

#[cfg(not(target_os = "linux"))]
compile_error!("vssb only supports Linux");

mod cgroup;
mod child;
mod config;
mod error;
mod landlock;
mod mounts;
mod prepare;
mod probe;
mod report;
pub mod seccomp;
mod spawn;
mod sys;

#[cfg(feature = "proxy")]
pub mod proxy;

pub use config::{Cgroup, Command, Limits, Mount, MountKind, Net, Resource, Sandbox, Stdio};
pub use error::{Error, Result};
pub use probe::{Support, probe};
pub use spawn::{Child, ExitStatus};
