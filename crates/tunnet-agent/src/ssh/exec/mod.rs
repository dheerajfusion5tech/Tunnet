//! Platform session launch after authorization.

use super::account::LocalAccount;

pub struct LaunchRequest {
    pub account: LocalAccount,
    pub term: String,
    pub width: u16,
    pub height: u16,
    pub env_vars: Vec<(String, String)>,
    pub command: Option<String>,
}

use crate::actors::ssh_registry::SessionKill;

pub struct SessionProcess {
    pub reader: Box<dyn std::io::Read + Send>,
    pub writer: Box<dyn std::io::Write + Send>,
    pub killer: Box<dyn SessionKill>,
    pub resize: Option<std::sync::mpsc::Sender<(u16, u16)>>,
}

#[cfg(unix)]
pub(crate) mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{spawn_sftp, spawn_shell};

#[cfg(windows)]
pub use windows::{spawn_sftp, spawn_shell};

#[cfg(not(any(unix, windows)))]
pub fn spawn_shell(_: &LaunchRequest) -> anyhow::Result<SessionProcess> {
    anyhow::bail!("SSH sessions are not supported on this platform");
}

#[cfg(not(any(unix, windows)))]
pub fn spawn_sftp(_: &LocalAccount) -> anyhow::Result<tokio::process::Child> {
    anyhow::bail!("SFTP is not supported on this platform");
}

pub fn child_argv() -> &'static str {
    "__ssh-session"
}

#[cfg(unix)]
pub fn sanitized_path() -> &'static str {
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

#[cfg(windows)]
pub fn sanitized_path() -> &'static str {
    r"C:\Windows\System32;C:\Windows"
}
