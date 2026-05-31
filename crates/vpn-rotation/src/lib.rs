use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Debug)]
pub struct CircuitDescriptor {
    pub id: Uuid,
    pub session_id: u64,
    pub remote: SocketAddr,
    pub path_id: u32,
    pub hops: usize,
    pub created_at: u64,
    pub epoch: u32,
}

impl CircuitDescriptor {
    pub fn new(session_id: u64, remote: SocketAddr, hops: usize, epoch: u32) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            remote,
            path_id: 1,
            hops,
            created_at: now_epoch_secs(),
            epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RotationState {
    Stable,
    Prepare,
    Migrate,
    Verify,
}

pub struct RotationManager {
    interval: Duration,
    grace: Duration,
    last_rotation: Instant,
    active: Option<CircuitDescriptor>,
    draining: Option<CircuitDescriptor>,
    state: RotationState,
}

impl RotationManager {
    pub fn new(interval: Duration, grace: Duration) -> Self {
        Self {
            interval,
            grace,
            last_rotation: Instant::now(),
            active: None,
            draining: None,
            state: RotationState::Stable,
        }
    }

    pub fn state(&self) -> RotationState {
        self.state
    }

    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    pub fn active(&self) -> Option<&CircuitDescriptor> {
        self.active.as_ref()
    }

    pub fn active_id(&self) -> Option<Uuid> {
        self.active.as_ref().map(|c| c.id)
    }

    pub fn is_due(&self) -> bool {
        self.last_rotation.elapsed() >= self.interval
    }

    pub fn install_initial(&mut self, circuit: CircuitDescriptor) {
        self.active = Some(circuit);
        self.state = RotationState::Stable;
        self.last_rotation = Instant::now();
    }

    pub fn begin_prepare(&mut self) {
        self.state = RotationState::Prepare;
    }

    pub fn begin_migrate(&mut self, next: CircuitDescriptor) {
        self.state = RotationState::Migrate;
        self.draining = self.active.replace(next);
    }

    pub fn begin_verify(&mut self) {
        self.state = RotationState::Verify;
    }

    pub fn abort(&mut self) {
        self.state = RotationState::Stable;
    }

    pub fn complete(&mut self) {
        self.state = RotationState::Stable;
        self.last_rotation = Instant::now();
    }

    pub fn draining(&self) -> Option<&CircuitDescriptor> {
        self.draining.as_ref()
    }

    pub fn grace(&self) -> Duration {
        self.grace
    }

    pub fn retire_draining_if_expired(&mut self) -> Option<CircuitDescriptor> {
        if let Some(circuit) = &self.draining {
            let elapsed = Duration::from_secs(now_epoch_secs().saturating_sub(circuit.created_at));
            if elapsed >= self.grace {
                return self.draining.take();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_enters_migrate_and_promotes_new_circuit() {
        let old_addr: SocketAddr = "127.0.0.1:7000".parse().expect("parse socket addr");
        let new_addr: SocketAddr = "127.0.0.1:7001".parse().expect("parse socket addr");
        let old = CircuitDescriptor::new(1, old_addr, 3, 1);
        let new = CircuitDescriptor::new(2, new_addr, 3, 2);
        let mut manager = RotationManager::new(Duration::from_secs(300), Duration::from_secs(30));

        manager.install_initial(old.clone());
        manager.begin_migrate(new.clone());

        assert_eq!(manager.state(), RotationState::Migrate);
        assert_eq!(manager.active().expect("active circuit").id, new.id);
        assert_eq!(manager.draining().expect("draining circuit").id, old.id);
    }
}
