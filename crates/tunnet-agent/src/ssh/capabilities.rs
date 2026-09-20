//! SSH session capabilities, independent of whether a login was authorized.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshCapabilities {
    pub shell: bool,
    pub exec: bool,
    pub sftp: bool,
    pub local_forward: bool,
    pub remote_forward: bool,
    pub agent_forward: bool,
    pub env_forward: bool,
}

impl SshCapabilities {
    /// Direct starts conservative: shell/exec/sftp, no forwarding.
    pub fn direct() -> Self {
        Self {
            shell: true,
            exec: true,
            sftp: true,
            local_forward: false,
            remote_forward: false,
            agent_forward: false,
            env_forward: true,
        }
    }

    pub fn managed() -> Self {
        Self::direct()
    }
}
