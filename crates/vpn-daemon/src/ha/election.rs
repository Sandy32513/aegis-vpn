use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

use super::{HaConfig, NodeRole, HaEvent, metrics};

pub struct LeaderElection {
    config: HaConfig,
    current_term: Arc<RwLock<u64>>,
    voted_for: Arc<RwLock<Option<String>>>,
    role: Arc<RwLock<NodeRole>>,
    last_heartbeat: Arc<RwLock<Instant>>,
    event_tx: mpsc::Sender<HaEvent>,
    running: Arc<RwLock<bool>>,
}

impl LeaderElection {
    pub fn new(config: HaConfig, event_tx: mpsc::Sender<HaEvent>) -> Self {
        Self {
            config,
            current_term: Arc::new(RwLock::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            role: Arc::new(RwLock::new(NodeRole::Follower)),
            last_heartbeat: Arc::new(RwLock::new(Instant::now())),
            event_tx,
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&mut self, mut rx: mpsc::Receiver<ElectionEvent>) {
        *self.running.write() = true;
        info!("election: starting leader election loop");

        loop {
            if !*self.running.read() {
                break;
            }

            tokio::select! {
                Some(event) = rx.recv() => {
                    self.handle_event(event).await;
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    self.check_election_timeout().await;
                }
            }
        }

        info!("election: leader election loop stopped");
    }

    pub fn stop(&mut self) {
        *self.running.write() = false;
    }

    async fn handle_event(&mut self, event: ElectionEvent) {
        match event {
            ElectionEvent::RequestVote { term, candidate_id, .. } => {
                self.handle_request_vote(term, candidate_id).await;
            }
            ElectionEvent::VoteGranted { .. } => {
                self.become_candidate().await;
            }
            ElectionEvent::Heartbeat { term, leader_id } => {
                self.handle_heartbeat(term, leader_id).await;
            }
            ElectionEvent::StartElection => {
                self.start_election().await;
            }
        }
    }

    async fn check_election_timeout(&mut self) {
        let elapsed = self.last_heartbeat.read().elapsed();
        let timeout = Duration::from_millis(self.config.election_timeout_ms);

        if elapsed > timeout && *self.role.read() != NodeRole::Leader {
            warn!("election: timeout expired, starting election");
            self.start_election().await;
        }
    }

    async fn start_election(&mut self) {
        let mut term = self.current_term.write();
        *term += 1;
        let current_term = *term;
        drop(term);

        info!("election: starting election for term {}", current_term);

        *self.voted_for.write() = Some(self.config.node_id.clone());
        self.become_candidate().await;

        let vote_requests = self.request_votes(current_term).await;
        
        if vote_requests >= self.config.peers.len() / 2 + 1 {
            self.become_leader().await;
        } else {
            metrics::inc_election_lost();
            warn!("election: lost, got {} votes needed {}", vote_requests, self.config.peers.len() / 2 + 1);
            self.become_follower().await;
        }
    }

    async fn request_votes(&self, term: u64) -> usize {
        let mut votes = 1;

        for peer in &self.config.peers {
            match self.send_vote_request(peer, term).await {
                Ok(true) => votes += 1,
                Ok(false) => {}
                Err(e) => {
                    debug!("election: vote request to {} failed: {}", peer, e);
                }
            }
        }

        votes
    }

    async fn send_vote_request(&self, peer: &str, term: u64) -> Result<bool, String> {
        Ok(true)
    }

    async fn handle_request_vote(&mut self, term: u64, candidate_id: String) {
        let mut current_term = self.current_term.write();

        if term > *current_term {
            *current_term = term;
            *self.voted_for.write() = Some(candidate_id);
            self.become_follower().await;
        }
    }

    async fn handle_heartbeat(&mut self, term: u64, leader_id: String) {
        let mut current_term = self.current_term.write();

        if term >= *current_term {
            *current_term = term;
            drop(current_term);
            
            *self.last_heartbeat.write() = Instant::now();
            
            if *self.role.read() != NodeRole::Follower {
                self.become_follower().await;
            }
            
            debug!("election: received heartbeat from leader {}", leader_id);
        }
    }

    async fn become_candidate(&mut self) {
        *self.role.write() = NodeRole::Candidate;
        info!("election: became candidate for term {}", *self.current_term.read());
    }

    async fn become_leader(&mut self) {
        let old_role = *self.role.read();
        *self.role.write() = NodeRole::Leader;
        
        info!("election: became leader for term {}", *self.current_term.read());
        
        metrics::inc_election_won();
        
        *self.last_heartbeat.write() = Instant::now();

        self.event_tx.send(HaEvent::RoleChanged {
            old_role,
            new_role: NodeRole::Leader,
        }).await.ok();
    }

    async fn become_follower(&mut self) {
        let old_role = *self.role.read();
        *self.role.write() = NodeRole::Follower;
        
        if old_role != NodeRole::Follower {
            info!("election: became follower");
            
            self.event_tx.send(HaEvent::RoleChanged {
                old_role,
                new_role: NodeRole::Follower,
            }).await.ok();
        }
        
        *self.last_heartbeat.write() = Instant::now();
    }

    pub fn get_role(&self) -> NodeRole {
        *self.role.read()
    }

    pub fn get_term(&self) -> u64 {
        *self.current_term.read()
    }
}

pub enum ElectionEvent {
    RequestVote { term: u64, candidate_id: String, last_log_index: u64, last_log_term: u64 },
    VoteGranted,
    Heartbeat { term: u64, leader_id: String },
    StartElection,
}