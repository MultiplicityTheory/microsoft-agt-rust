use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

struct InnerState {
    state: CircuitState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
}

pub struct CircuitBreaker {
    inner: Arc<RwLock<InnerState>>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerState {
                state: CircuitState::Closed,
                failure_count: 0,
                last_failure_time: None,
            })),
            failure_threshold,
            reset_timeout,
        }
    }

    pub fn is_allowed(&self) -> bool {
        let mut inner = self.inner.write().unwrap();
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(time) = inner.last_failure_time {
                    if time.elapsed() >= self.reset_timeout {
                        // Switch to half-open to test recovery
                        inner.state = CircuitState::HalfOpen;
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
        let mut inner = self.inner.write().unwrap();
        inner.state = CircuitState::Closed;
        inner.failure_count = 0;
    }

    pub fn record_failure(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.failure_count += 1;
        if inner.failure_count >= self.failure_threshold {
            inner.state = CircuitState::Open;
            inner.last_failure_time = Some(Instant::now());
        }
    }

    // Helper for testing or status reporting
    pub fn state(&self) -> CircuitState {
        self.inner.read().unwrap().state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_flow() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(100));
        
        assert!(cb.is_allowed());
        
        cb.record_failure();
        assert!(cb.is_allowed());
        
        cb.record_failure();
        assert!(!cb.is_allowed()); // Should be Open now
        assert_eq!(cb.state(), CircuitState::Open);
        
        std::thread::sleep(Duration::from_millis(150));
        
        assert!(cb.is_allowed()); // Should transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
