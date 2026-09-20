//! Unix incubator: drop privileges in a child of `tunnetd`, then exec.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

use super::{LaunchRequest, SessionProcess, child_argv, sanitized_path};
use crate::actors::ssh_registry::SessionKill;
use crate::ssh::account::LocalAccount;

struct ChildKiller {
    child: std::sync::Arc<std::sync::Mutex<std::process::Child>>,
}

impl SessionKill for ChildKiller {
    fn kill(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

pub fn spawn_shell(req: &LaunchRequest) -> anyhow::Result<SessionProcess> {
    let (master, slave) = open_pty(req.width, req.height)?;
    let exe = std::env::current_exe().context("resolve tunnetd for SSH session")?;
    let mut cmd = Command::new(exe);
    cmd.arg(child_argv());
    cmd.env_clear();
    cmd.env("PATH", sanitized_path());
    cmd.env("TERM", &req.term);
    cmd.env("HOME", &req.account.home_dir);
    cmd.env("USER", &req.account.username);
    cmd.env("LOGNAME", &req.account.username);
    cmd.env("SHELL", &req.account.shell);
    cmd.env("TUNNET_SSH_UID", req.account.uid.to_string());
    cmd.env("TUNNET_SSH_GID", req.account.gid.to_string());
    cmd.env(
        "TUNNET_SSH_GROUPS",
        req.account
            .groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    cmd.env("TUNNET_SSH_USER", &req.account.username);
    cmd.env("TUNNET_SSH_HOME", &req.account.home_dir);
    cmd.env("TUNNET_SSH_SHELL", &req.account.shell);
    if let Some(command) = &req.command {
        cmd.env("TUNNET_SSH_EXEC", command);
    } else {
        cmd.env("TUNNET_SSH_LOGIN", "1");
    }
    for (k, v) in &req.env_vars {
        cmd.env(k, v);
    }
    let slave_in = slave.try_clone().context("clone pty slave")?;
    let slave_err = slave.try_clone().context("clone pty slave")?;
    cmd.stdin(Stdio::from(slave_in));
    cmd.stdout(Stdio::from(slave));
    cmd.stderr(Stdio::from(slave_err));
    let child = cmd.spawn().context("spawn SSH session child")?;
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let reader = master.try_clone().context("clone pty master")?;
    let (resize_tx, resize_rx) = std::sync::mpsc::channel::<(u16, u16)>();
    let resize_fd = master.as_raw_fd();
    std::thread::spawn(move || {
        while let Ok((cols, rows)) = resize_rx.recv() {
            let mut size = libc::winsize {
                ws_row: rows.max(1),
                ws_col: cols.max(1),
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                libc::ioctl(resize_fd, libc::TIOCSWINSZ, &mut size);
            }
        }
    });
    Ok(SessionProcess {
        reader: Box::new(reader),
        writer: Box::new(master),
        killer: Box::new(ChildKiller { child }),
        resize: Some(resize_tx),
    })
}

pub fn spawn_sftp(account: &LocalAccount) -> anyhow::Result<tokio::process::Child> {
    let exe = std::env::current_exe().context("resolve tunnetd for SFTP session")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(child_argv());
    cmd.env_clear();
    cmd.env("PATH", sanitized_path());
    cmd.env("HOME", &account.home_dir);
    cmd.env("USER", &account.username);
    cmd.env("LOGNAME", &account.username);
    cmd.env("SHELL", &account.shell);
    cmd.env("TUNNET_SSH_UID", account.uid.to_string());
    cmd.env("TUNNET_SSH_GID", account.gid.to_string());
    cmd.env(
        "TUNNET_SSH_GROUPS",
        account
            .groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    cmd.env("TUNNET_SSH_USER", &account.username);
    cmd.env("TUNNET_SSH_HOME", &account.home_dir);
    cmd.env("TUNNET_SSH_SHELL", &account.shell);
    cmd.env("TUNNET_SSH_SFTP", "1");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.spawn().context("spawn SFTP session child")
}

fn open_pty(cols: u16, rows: u16) -> anyhow::Result<(File, File)> {
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_fd < 0 {
        bail!("posix_openpt failed: {}", std::io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master_fd) };
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0
        || unsafe { libc::unlockpt(master.as_raw_fd()) } != 0
    {
        bail!(
            "grantpt/unlockpt failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut name = vec![0u8; 128];
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr().cast(), name.len()) } != 0
        {
            bail!("ptsname_r failed: {}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let ptr = unsafe { libc::ptsname(master.as_raw_fd()) };
        if ptr.is_null() {
            bail!("ptsname failed: {}", std::io::Error::last_os_error());
        }
        let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
        let bytes = cstr.to_bytes_with_nul();
        name[..bytes.len()].copy_from_slice(bytes);
    }
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let path = std::ffi::CString::new(&name[..end]).context("pty name")?;
    let slave_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave_fd < 0 {
        bail!("open pty slave failed: {}", std::io::Error::last_os_error());
    }
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    let mut size = libc::winsize {
        ws_row: rows.max(1),
        ws_col: cols.max(1),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &mut size);
    }
    let master = File::from(master);
    Ok((master, slave))
}

pub fn drop_privileges(uid: u32, gid: u32, groups: &[u32]) -> anyhow::Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 && euid != uid {
        bail!("cannot switch to uid {uid} from unprivileged euid {euid}");
    }
    let mut gids: Vec<libc::gid_t> = groups.to_vec();
    if !gids.contains(&gid) {
        gids.insert(0, gid);
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        gids.retain(|g| *g != gid);
        gids.insert(0, gid);
        if gids.len() > 16 {
            gids.truncate(16);
        }
    }
    if unsafe { libc::setgroups(gids.len() as _, gids.as_ptr()) } != 0 && euid == 0 {
        bail!("setgroups failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::setgid(gid) } != 0 {
        bail!("setgid({gid}) failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::setuid(uid) } != 0 {
        bail!("setuid({uid}) failed: {}", std::io::Error::last_os_error());
    }
    let got_uid = unsafe { libc::geteuid() };
    let got_gid = unsafe { libc::getegid() };
    if got_uid != uid || got_gid != gid {
        bail!("privilege drop verification failed (uid {got_uid} gid {got_gid}, want {uid}/{gid})");
    }
    Ok(())
}

pub fn become_session() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    let tiocsctty = libc::c_ulong::from(libc::TIOCSCTTY);
    #[cfg(not(target_os = "macos"))]
    let tiocsctty = libc::TIOCSCTTY;
    unsafe {
        libc::setsid();
        libc::ioctl(0, tiocsctty, 0);
    }
    Ok(())
}

pub fn exec_shell(
    login: bool,
    command: Option<&str>,
    shell: &std::path::Path,
) -> anyhow::Result<()> {
    let mut cmd = Command::new(shell);
    if let Some(command) = command {
        cmd.arg("-c");
        cmd.arg(command);
    } else if login {
        cmd.arg("-l");
    }
    let err = cmd.exec();
    Err(err).context("exec shell")
}

#[cfg(test)]
mod tests {
    use super::drop_privileges;

    #[test]
    fn same_user_drop_is_idempotent() {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        drop_privileges(uid, gid, &[gid]).unwrap();
        assert_eq!(unsafe { libc::geteuid() }, uid);
        assert_eq!(unsafe { libc::getegid() }, gid);
    }
}
