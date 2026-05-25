use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    failure_threshold: u32,
    failure_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_threshold,
            failure_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            reset_timeout,
        }
    }

    pub fn is_allowed(&self) -> bool {
        let state = *self.state.read().unwrap();
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last_failure = *self.last_failure_time.read().unwrap();
                if let Some(time) = last_failure {
                    if time.elapsed() >= self.reset_timeout {
                        // Switch to half-open to test recovery
                        let mut state = self.state.write().unwrap();
                        *state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub fn record_success(&self) {
        let mut state = self.state.write().unwrap();
        *state = CircuitState::Closed;
        let mut failure_count = self.failure_count.write().unwrap();
        *failure_count = 0;
    }

    pub fn record_failure(&self) {
        let mut failure_count = self.failure_count.write().unwrap();
        *failure_count += 1;
        if *failure_count >= self.failure_threshold {
            let mut state = self.state.write().unwrap();
            *state = CircuitState::Open;
            let mut last_failure_time = self.last_failure_time.write().unwrap();
            *last_failure_time = Some(Instant::now());
        }
    }
}
