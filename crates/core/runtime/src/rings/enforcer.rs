#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivilegeRing {
    System = 0,
    Trusted = 1,
    Standard = 2,
    Sandboxed = 3,
}

pub struct Enforcer;

impl Enforcer {
    pub fn can_execute(ring: PrivilegeRing, required_ring: PrivilegeRing) -> bool {
        ring <= required_ring
    }
}
