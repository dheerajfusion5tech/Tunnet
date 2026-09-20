//! Privileged-drop child of `tunnetd` (`tunnetd __ssh-session`).
//!
//! The multithreaded agent execs this process instead of forking, then this
//! process becomes the destination user and execs the shell or SFTP handler.

pub fn maybe_run() -> bool {
    let mut args = std::env::args();
    let _exe = args.next();
    match args.next().as_deref() {
        Some("__ssh-session") => {
            if let Err(error) = run() {
                eprintln!("tunnet ssh-session: {error:#}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        _ => false,
    }
}

fn run() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        run_unix()
    }
    #[cfg(windows)]
    {
        run_windows()
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("SSH session child is not supported on this platform")
    }
}

#[cfg(unix)]
fn run_unix() -> anyhow::Result<()> {
    use super::exec::unix::{become_session, drop_privileges, exec_shell};

    let uid: u32 = env_parse("TUNNET_SSH_UID")?;
    let gid: u32 = env_parse("TUNNET_SSH_GID")?;
    let groups = std::env::var("TUNNET_SSH_GROUPS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()?;
    let home =
        std::path::PathBuf::from(std::env::var("TUNNET_SSH_HOME").unwrap_or_else(|_| "/".into()));
    let shell = std::path::PathBuf::from(
        std::env::var("TUNNET_SSH_SHELL").unwrap_or_else(|_| "/bin/sh".into()),
    );
    let sftp = std::env::var_os("TUNNET_SSH_SFTP").is_some();
    let login = std::env::var_os("TUNNET_SSH_LOGIN").is_some();
    let command = std::env::var("TUNNET_SSH_EXEC").ok();

    if !sftp {
        become_session()?;
    }
    drop_privileges(uid, gid, &groups)?;
    if std::env::set_current_dir(&home).is_err() {
        let _ = std::env::set_current_dir("/");
        // SAFETY: this process is the dedicated SSH session child; no other
        // threads exist yet and the environment is owned by this process.
        unsafe {
            std::env::set_var("HOME", "/");
        }
    }
    if sftp {
        return run_sftp();
    }
    exec_shell(login, command.as_deref(), &shell)
}

#[cfg(windows)]
fn run_windows() -> anyhow::Result<()> {
    if std::env::var_os("TUNNET_SSH_SFTP").is_some() {
        return run_sftp();
    }
    anyhow::bail!(
        "Windows interactive sessions are launched with CreateProcessAsUser, not this child"
    )
}

fn run_sftp() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let stream = StdioDuplex {
            reader: tokio::io::stdin(),
            writer: tokio::io::stdout(),
        };
        let home = std::env::var("TUNNET_SSH_HOME").unwrap_or_else(|_| "/".into());
        let user = std::env::var("TUNNET_SSH_USER").unwrap_or_else(|_| "user".into());
        let handler = super::sftp::SftpSession::for_account(user, home.into())?;
        russh_sftp::server::run(stream, handler).await;
        Ok(())
    })
}

struct StdioDuplex {
    reader: tokio::io::Stdin,
    writer: tokio::io::Stdout,
}

impl tokio::io::AsyncRead for StdioDuplex {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StdioDuplex {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(unix)]
fn env_parse<T: std::str::FromStr>(key: &str) -> anyhow::Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value = std::env::var(key)?;
    Ok(value.parse()?)
}
