//! Destination-side Tunnet SSH server (russh on mesh IP + TUN port NAT).
//!
//! Byte I/O stays direct async code. Session lifecycle (IDs, kill handles,
//! metadata, control-plane kills) is owned by `actors::SshRegistryActor`.

mod host_key;
mod listener;
mod pty;
mod server;
mod sftp;
mod tee;
mod user;

pub use host_key::host_pubkey_openssh;
pub use listener::spawn_ssh_listener;
pub use server::{SshAuthorization, SshServeDeps};
