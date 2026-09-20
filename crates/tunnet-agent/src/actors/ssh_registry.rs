//! `SshRegistryActor`: owns active SSH session lifecycle.
//!
//! Byte I/O (russh handlers, PTY pumps, SFTP, recording) stays direct async
//! code. This actor owns low-volume registry state: session IDs, kill
//! handles, metadata, control-plane kill commands, and cleanup.

use std::collections::{HashMap, HashSet};

use kameo::actor::{Actor, ActorRef};
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use uuid::Uuid;

#[derive(Debug, Clone, kameo::Reply)]
#[allow(dead_code)]
pub struct SessionMeta {
    pub id: Uuid,
    pub peer_hex: String,
    pub target_user: String,
}

pub trait SessionKill: Send + Sync {
    fn kill(&mut self);
}

pub struct SshRegistryActor {
    // Killers are not Clone, so restarts begin empty (sessions do not survive
    // actor restart; new connections re-register). Metadata mirrors killers.
    killers: HashMap<Uuid, Box<dyn SessionKill>>,
    meta: HashMap<Uuid, SessionMeta>,
    killed: HashSet<Uuid>,
}

impl Actor for SshRegistryActor {
    type Args = ();
    type Error = Infallible;

    async fn on_start(_args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            killers: HashMap::new(),
            meta: HashMap::new(),
            killed: HashSet::new(),
        })
    }
}

impl SshRegistryActor {}

pub struct RegisterSession {
    pub id: Uuid,
    pub peer_hex: String,
    pub target_user: String,
    pub killer: Box<dyn SessionKill>,
}

pub struct UnregisterSession {
    pub id: Uuid,
}

pub struct KillSession {
    pub session_id: String,
}

pub struct ListSessions;
pub struct ShutdownSshRegistry;

/// Unregister a finished session; returns true if it had been killed via
/// `KillSession` (caller should skip duplicate kill logging).
pub struct SessionEnded {
    pub id: Uuid,
}

impl Message<RegisterSession> for SshRegistryActor {
    type Reply = ();
    async fn handle(&mut self, msg: RegisterSession, _ctx: &mut Context<Self, Self::Reply>) {
        self.meta.insert(
            msg.id,
            SessionMeta {
                id: msg.id,
                peer_hex: msg.peer_hex,
                target_user: msg.target_user,
            },
        );
        self.killers.insert(msg.id, msg.killer);
    }
}

impl Message<UnregisterSession> for SshRegistryActor {
    type Reply = ();
    async fn handle(&mut self, msg: UnregisterSession, _ctx: &mut Context<Self, Self::Reply>) {
        self.killers.remove(&msg.id);
        self.meta.remove(&msg.id);
    }
}

impl Message<KillSession> for SshRegistryActor {
    type Reply = bool;
    async fn handle(
        &mut self,
        msg: KillSession,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Ok(id) = Uuid::parse_str(&msg.session_id) else {
            tracing::warn!(session_id = %msg.session_id, "KillSshSession: invalid session id");
            return false;
        };
        if let Some(mut killer) = self.killers.remove(&id) {
            self.meta.remove(&id);
            self.killed.insert(id);
            killer.kill();
            tracing::info!(%id, "killed SSH session by CP request");
            true
        } else {
            tracing::debug!(%id, "KillSshSession: session not found locally");
            false
        }
    }
}

impl Message<ListSessions> for SshRegistryActor {
    type Reply = Vec<SessionMeta>;
    async fn handle(
        &mut self,
        _msg: ListSessions,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.meta.values().cloned().collect()
    }
}

impl Message<SessionEnded> for SshRegistryActor {
    type Reply = bool;
    async fn handle(
        &mut self,
        msg: SessionEnded,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.killers.remove(&msg.id);
        self.meta.remove(&msg.id);
        self.killed.remove(&msg.id)
    }
}

impl Message<ShutdownSshRegistry> for SshRegistryActor {
    type Reply = ();
    async fn handle(&mut self, _msg: ShutdownSshRegistry, ctx: &mut Context<Self, Self::Reply>) {
        ctx.stop();
    }
}
