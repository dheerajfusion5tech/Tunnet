//! Resolve a destination OS account. Never uses the agent process environment.

use std::path::PathBuf;

use anyhow::bail;

#[derive(Debug, Clone)]
pub struct LocalAccount {
    pub username: String,
    pub home_dir: PathBuf,
    pub shell: PathBuf,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    #[cfg(unix)]
    pub groups: Vec<u32>,
    #[cfg(windows)]
    pub sid: String,
}

pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
    let username = username.trim();
    if username.is_empty() {
        bail!("empty username");
    }
    #[cfg(unix)]
    {
        unix::resolve(username)
    }
    #[cfg(windows)]
    {
        windows::resolve(username)
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("OS account lookup is not supported on this platform");
    }
}

/// Interactive local accounts for Managed `autogroup:local`.
pub fn interactive_usernames() -> Vec<String> {
    #[cfg(unix)]
    {
        unix::interactive_usernames()
    }
    #[cfg(windows)]
    {
        windows::interactive_usernames()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

#[cfg(unix)]
mod unix {
    use super::LocalAccount;
    use anyhow::{Context, bail};
    use std::ffi::{CStr, CString};
    use std::path::PathBuf;

    pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
        let c_user = CString::new(username).context("username")?;
        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut buf = vec![0u8; 16 * 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwnam_r writes into pwd/buf and sets result on success.
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            bail!("user `{username}` not found");
        }
        // SAFETY: result is non-null and aliases pwd.
        let pwd = unsafe { &*result };
        let username = cstr(pwd.pw_name)?.to_string();
        let home_dir = PathBuf::from(cstr(pwd.pw_dir)?.to_string());
        let shell = {
            let s = cstr(pwd.pw_shell)?.to_string();
            if s.is_empty() {
                PathBuf::from("/bin/sh")
            } else {
                PathBuf::from(s)
            }
        };
        let uid = pwd.pw_uid;
        let gid = pwd.pw_gid;
        let groups = supplementary_groups(&username, gid);
        Ok(LocalAccount {
            username,
            home_dir,
            shell,
            uid,
            gid,
            groups,
        })
    }

    fn supplementary_groups(username: &str, gid: u32) -> Vec<u32> {
        let Ok(c_user) = CString::new(username) else {
            return vec![gid];
        };
        let mut n = 64i32;
        let mut groups: Vec<libc::gid_t> = vec![0; n as usize];
        // SAFETY: getgrouplist fills `groups` up to `n`.
        let rc = unsafe { libc::getgrouplist(c_user.as_ptr(), gid, groups.as_mut_ptr(), &mut n) };
        if rc < 0 {
            groups.resize(n.max(1) as usize, 0);
            let rc =
                unsafe { libc::getgrouplist(c_user.as_ptr(), gid, groups.as_mut_ptr(), &mut n) };
            if rc < 0 {
                return vec![gid];
            }
        }
        groups.truncate(n as usize);
        let mut out = groups;
        if !out.contains(&gid) {
            out.insert(0, gid);
        }
        out
    }

    pub fn interactive_usernames() -> Vec<String> {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Vec::new();
        }
        resolve_uid(euid)
            .map(|a| vec![a.username])
            .unwrap_or_default()
    }

    fn resolve_uid(uid: u32) -> anyhow::Result<LocalAccount> {
        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut buf = vec![0u8; 16 * 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            bail!("uid {uid} not found");
        }
        let pwd = unsafe { &*result };
        let username = cstr(pwd.pw_name)?.to_string();
        resolve(&username)
    }

    fn cstr(ptr: *const libc::c_char) -> anyhow::Result<String> {
        if ptr.is_null() {
            return Ok(String::new());
        }
        Ok(unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned())
    }
}

#[cfg(windows)]
mod windows {
    use super::LocalAccount;
    use anyhow::{Context, bail};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, SidTypeUser};
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName,
    };

    pub fn resolve(username: &str) -> anyhow::Result<LocalAccount> {
        let sid = lookup_sid(username)?;
        let home_dir = std::env::var_os("SYSTEMDRIVE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:"));
        Ok(LocalAccount {
            username: username.to_string(),
            home_dir,
            shell: PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            sid,
        })
    }

    pub fn interactive_usernames() -> Vec<String> {
        logged_on_usernames()
    }

    fn lookup_sid(username: &str) -> anyhow::Result<String> {
        let wide: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_use = 0i32;
        unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                wide.as_ptr(),
                std::ptr::null_mut(),
                &mut sid_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut sid_use,
            );
        }
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
            bail!("Windows account `{username}` not found");
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                wide.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if ok == 0 {
            bail!("Windows account `{username}` not found");
        }
        if sid_use != SidTypeUser {
            bail!("`{username}` is not a user account");
        }
        let mut sid_str: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut sid_str) };
        if ok == 0 || sid_str.is_null() {
            bail!("could not encode SID for `{username}`");
        }
        let encoded = wide_ptr_to_string(sid_str);
        unsafe { LocalFree(sid_str.cast()) };
        encoded.context("SID string")
    }

    fn logged_on_usernames() -> Vec<String> {
        let mut info = std::ptr::null_mut();
        let mut count = 0u32;
        let ok = unsafe {
            WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count)
        };
        if ok == 0 || info.is_null() {
            return Vec::new();
        }
        let mut names = Vec::new();
        for i in 0..count {
            let session = unsafe { &*info.add(i as usize) };
            if session.State != WTSActive {
                continue;
            }
            let mut buf = std::ptr::null_mut();
            let mut bytes = 0u32;
            let ok = unsafe {
                WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    session.SessionId,
                    WTSUserName,
                    &mut buf,
                    &mut bytes,
                )
            };
            if ok != 0 && !buf.is_null() {
                if let Ok(name) = wide_ptr_to_string(buf.cast())
                    && !name.is_empty()
                {
                    names.push(name);
                }
                unsafe { WTSFreeMemory(buf.cast()) };
            }
        }
        unsafe { WTSFreeMemory(info.cast()) };
        names.sort();
        names.dedup();
        names
    }

    fn wide_ptr_to_string(ptr: *const u16) -> anyhow::Result<String> {
        if ptr.is_null() {
            bail!("null wide string");
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Ok(std::ffi::OsString::from_wide(slice)
            .to_string_lossy()
            .into_owned())
    }
}
