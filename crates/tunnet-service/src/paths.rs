use std::path::{Path, PathBuf};

/// System-wide state directory used by the Tunnet service.
pub fn system_state_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/tunnet")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
        PathBuf::from(base).join("tunnet")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("./tunnet-state")
    }
}

pub fn resolve_state_dir(state_dir: Option<&str>) -> PathBuf {
    state_dir
        .map(PathBuf::from)
        .unwrap_or_else(system_state_dir)
}

fn daemon_name() -> &'static str {
    if cfg!(windows) {
        "tunnetd.exe"
    } else {
        "tunnetd"
    }
}

#[cfg(windows)]
fn cli_name() -> &'static str {
    "tunnet.exe"
}

/// Canonical directory for service/daemon binaries on Windows.
///
/// Layout (Windows): `%ProgramData%\tunnet\bin\` holds the *active* copies of
/// `tunnet.exe` and `tunnetd.exe`. SCM always points at `tunnetd.exe` here.
/// The desktop app may live under Program Files / NSIS `$INSTDIR`;
/// install/update paths must stage into this directory via [`stage_daemon_exe`]
/// so users never have competing "active" daemon copies.
#[cfg(windows)]
pub fn installed_bin_dir(state_dir: Option<&str>) -> PathBuf {
    resolve_state_dir(state_dir).join("bin")
}

#[cfg(windows)]
pub fn installed_daemon_exe(state_dir: Option<&str>) -> PathBuf {
    installed_bin_dir(state_dir).join(daemon_name())
}

fn path_is_release(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "release")
}

fn newest_workspace_daemon(start: &Path, name: &str) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if !path.is_file() {
            return;
        }
        let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
            return;
        };
        let take = match &best {
            None => true,
            Some((best_time, best_path)) => {
                modified > *best_time
                    || (modified == *best_time
                        && path_is_release(&path)
                        && !path_is_release(best_path))
            }
        };
        if take {
            best = Some((modified, path));
        }
    };

    consider(start.join(name));
    for ancestor in start.ancestors() {
        for profile in ["debug", "release"] {
            consider(ancestor.join("target").join(profile).join(name));
        }
    }
    best.map(|(_, path)| path)
}

pub fn resolve_daemon_exe() -> anyhow::Result<PathBuf> {
    let name = daemon_name();
    if let Ok(current) = std::env::current_exe()
        && let Some(dir) = current.parent()
        && let Some(found) = newest_workspace_daemon(dir, name)
    {
        return Ok(found);
    }
    if let Some(path) = find_on_path(name) {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        let staged = installed_daemon_exe(None);
        if staged.is_file() {
            return Ok(staged);
        }
    }
    anyhow::bail!("could not find {name}; place it next to tunnet or on PATH")
}

#[cfg(windows)]
pub fn daemon_outdated(state_dir: Option<&str>) -> anyhow::Result<bool> {
    let source = resolve_daemon_exe()?;
    let dest = installed_daemon_exe(state_dir);
    // Source may already *be* the staged binary (e.g. running from ProgramData).
    let source_canon = source.canonicalize().unwrap_or_else(|_| source.clone());
    let dest_canon = dest.canonicalize().unwrap_or_else(|_| dest.clone());
    if source_canon == dest_canon {
        return Ok(false);
    }
    if !dest.is_file() {
        return Ok(true);
    }
    Ok(!same_artifact(&source, &dest))
}

/// Stage daemon and CLI into [`installed_bin_dir`] and return the
/// staged `tunnetd` path. This is the only path SCM should run.
#[cfg(windows)]
pub fn stage_daemon_exe(state_dir: Option<&str>) -> anyhow::Result<PathBuf> {
    let source = {
        let s = resolve_daemon_exe()?;
        s.canonicalize().unwrap_or(s)
    };
    let dest_dir = installed_bin_dir(state_dir);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", dest_dir.display()))?;
    let dest = installed_daemon_exe(state_dir);

    let source_is_dest = source
        .canonicalize()
        .ok()
        .zip(dest.canonicalize().ok())
        .is_some_and(|(a, b)| a == b);
    if !source_is_dest {
        tunnet_common::persistence::atomic_copy(&source, &dest).map_err(|error| {
            anyhow::anyhow!("copy {} to {}: {error}", source.display(), dest.display())
        })?;
    }

    if let Some(dir) = source.parent() {
        let cli = dir.join(cli_name());
        if cli.is_file() {
            let cli_dest = dest_dir.join(cli_name());
            tunnet_common::persistence::atomic_copy(&cli, &cli_dest).map_err(|error| {
                anyhow::anyhow!("copy {} to {}: {error}", cli.display(), cli_dest.display())
            })?;
        }
    }

    Ok(dest)
}

/// Wipe enrollment/config state under `dir`, preserving `bin/` (staged service binaries).
pub fn wipe_state_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?;
        let path = entry.path();
        if entry.file_name() == "bin" {
            continue;
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path).map_err(|e| {
                anyhow::anyhow!("wipe {} (is tunnetd still running?): {e}", path.display())
            })?;
        } else {
            std::fs::remove_file(&path).map_err(|e| {
                anyhow::anyhow!("wipe {} (is tunnetd still running?): {e}", path.display())
            })?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn same_artifact(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    match (ma.modified(), mb.modified()) {
        (Ok(ta), Ok(tb)) => ta == tb,
        _ => false,
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{newest_workspace_daemon, system_state_dir};

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunnet-ws-daemon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn daemon_name_for_tests() -> &'static str {
        if cfg!(windows) {
            "tunnetd.exe"
        } else {
            "tunnetd"
        }
    }

    #[test]
    fn workspace_daemon_is_found_from_nested_desktop_target() {
        let root = test_root();
        let name = daemon_name_for_tests();
        let daemon = root.join("target").join("debug").join(name);
        std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
        std::fs::write(&daemon, b"daemon").unwrap();
        let desktop_dir = root
            .join("apps")
            .join("desktop")
            .join("src-tauri")
            .join("target")
            .join("debug");
        std::fs::create_dir_all(&desktop_dir).unwrap();
        let found = newest_workspace_daemon(&desktop_dir, name);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found.as_deref(), Some(daemon.as_path()));
    }

    #[test]
    fn newer_release_tunnetd_wins_over_stale_debug_sibling() {
        let root = test_root();
        let name = daemon_name_for_tests();
        let debug_dir = root.join("target").join("debug");
        let release_dir = root.join("target").join("release");
        std::fs::create_dir_all(&debug_dir).unwrap();
        std::fs::create_dir_all(&release_dir).unwrap();
        let debug = debug_dir.join(name);
        let release = release_dir.join(name);
        std::fs::write(&debug, b"old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(&release, b"new").unwrap();
        let found = newest_workspace_daemon(&debug_dir, name);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found.as_deref(), Some(release.as_path()));
    }

    #[test]
    fn system_dir_matches_platform() {
        #[cfg(unix)]
        assert_eq!(
            system_state_dir(),
            std::path::PathBuf::from("/var/lib/tunnet")
        );
        #[cfg(windows)]
        {
            let dir = system_state_dir();
            assert!(dir.ends_with("tunnet"), "got {}", dir.display());
        }
    }
}
