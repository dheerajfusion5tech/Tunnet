//! TCP listener for Tunnet SSH on mesh_ip:SSH_INTERNAL_PORT.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use russh::server::Config;
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;

use super::host_key::load_or_create_host_key;
use super::server::{SshHandler, SshServeDeps};
use crate::ssh_nat::SSH_INTERNAL_PORT;

pub async fn spawn_ssh_listener(
    mesh_addrs: &HashMap<Ipv4Addr, uuid::Uuid>,
    paths: &tunnet_core::StatePaths,
    deps: SshServeDeps,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let host_key = load_or_create_host_key(paths)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::None);
    methods.push(MethodKind::KeyboardInteractive);

    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        methods,
        ..Default::default()
    });

    anyhow::ensure!(!mesh_addrs.is_empty(), "no active mesh addresses for SSH");
    let mut listeners = Vec::with_capacity(mesh_addrs.len());
    for (&mesh_ip, &network_id) in mesh_addrs {
        let listener = TcpListener::bind((mesh_ip, SSH_INTERNAL_PORT)).await?;
        tracing::info!(%mesh_ip, %network_id, port = SSH_INTERNAL_PORT, "SSH server listening (NAT maps :22)");
        listeners.push((listener, network_id));
    }

    let handle = tokio::spawn(async move {
        for (listener, network_id) in listeners {
            let config = config.clone();
            let mut deps = deps.clone();
            if matches!(
                deps.authorization,
                super::server::SshAuthorization::Direct { .. }
            ) {
                let local_user = current_local_user();
                deps.authorization = super::server::SshAuthorization::Direct {
                    local_network: network_id,
                    local_user,
                };
            }
            tokio::spawn(async move {
                loop {
                    let (socket, peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(?e, %network_id, "ssh accept failed");
                            continue;
                        }
                    };
                    let local = socket
                        .local_addr()
                        .unwrap_or_else(|_| (Ipv4Addr::UNSPECIFIED, SSH_INTERNAL_PORT).into());
                    let config = config.clone();
                    let deps = deps.clone();
                    tokio::spawn(async move {
                        let handler = SshHandler::new(deps, peer, local);
                        match russh::server::run_stream(config, socket, handler).await {
                            Ok(session) => {
                                if let Err(e) = session.await {
                                    tracing::debug!(?e, %peer, "ssh session ended");
                                }
                            }
                            Err(e) => {
                                tracing::debug!(?e, %peer, "ssh handshake failed");
                            }
                        }
                    });
                }
            });
        }
    });
    Ok(handle)
}

fn current_local_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}
