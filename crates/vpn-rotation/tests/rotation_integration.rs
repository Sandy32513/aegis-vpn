use std::net::SocketAddr;
use std::time::Duration;
use vpn_rotation::*;

fn make_descriptor(session_id: u64, epoch: u32) -> CircuitDescriptor {
    let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
    CircuitDescriptor::new(session_id, addr, 3, epoch)
}

#[test]
fn initial_install_is_stable() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    let d = make_descriptor(1, 1);
    mgr.install_initial(d.clone());
    assert_eq!(mgr.state(), RotationState::Stable);
    assert_eq!(mgr.active().unwrap().id, d.id);
    assert!(mgr.draining().is_none());
}

#[test]
fn rotation_not_due_immediately() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    mgr.install_initial(make_descriptor(1, 1));
    assert!(!mgr.is_due());
}

#[test]
fn migration_drains_old_circuit() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    let old = make_descriptor(1, 1);
    let new = make_descriptor(2, 2);
    mgr.install_initial(old.clone());

    mgr.begin_migrate(new.clone());
    assert_eq!(mgr.state(), RotationState::Migrate);
    assert_eq!(mgr.active().unwrap().id, new.id);
    assert_eq!(mgr.draining().unwrap().id, old.id);
}

#[test]
fn full_rotation_lifecycle() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    let old = make_descriptor(1, 1);
    let new = make_descriptor(2, 2);
    mgr.install_initial(old);

    mgr.begin_prepare();
    assert_eq!(mgr.state(), RotationState::Prepare);

    mgr.begin_migrate(new.clone());
    assert_eq!(mgr.state(), RotationState::Migrate);
    assert!(mgr.draining().is_some());

    mgr.begin_verify();
    assert_eq!(mgr.state(), RotationState::Verify);

    mgr.complete();
    assert_eq!(mgr.state(), RotationState::Stable);
    assert!(mgr.draining().is_some()); // still draining until grace period
}

#[test]
fn abort_returns_to_stable() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    mgr.install_initial(make_descriptor(1, 1));
    mgr.begin_prepare();
    assert_eq!(mgr.state(), RotationState::Prepare);
    mgr.abort();
    assert_eq!(mgr.state(), RotationState::Stable);
}

#[test]
fn retire_draining_after_grace() {
    let mut mgr = RotationManager::new(Duration::from_secs(0), Duration::from_secs(0));
    let old = make_descriptor(1, 1);
    let new = make_descriptor(2, 2);
    mgr.install_initial(old);
    mgr.begin_migrate(new);
    mgr.complete();

    // With 0 grace period, should be immediately retirable
    let retired = mgr.retire_draining_if_expired();
    assert!(retired.is_some());
}

#[test]
fn set_interval_changes_behavior() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    mgr.install_initial(make_descriptor(1, 1));
    assert!(!mgr.is_due());

    mgr.set_interval(Duration::from_secs(0));
    assert!(mgr.is_due());
}

#[test]
fn active_id_matches() {
    let mut mgr = RotationManager::new(Duration::from_secs(300), Duration::from_secs(90));
    let d = make_descriptor(42, 1);
    mgr.install_initial(d.clone());
    assert_eq!(mgr.active_id(), Some(d.id));
}

#[test]
fn circuit_descriptor_fields() {
    let addr: SocketAddr = "192.168.1.1:5555".parse().unwrap();
    let d = CircuitDescriptor::new(99, addr, 5, 3);
    assert_eq!(d.session_id, 99);
    assert_eq!(d.remote, addr);
    assert_eq!(d.hops, 5);
    assert_eq!(d.epoch, 3);
    assert_eq!(d.path_id, 1);
}
