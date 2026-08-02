//! Capability model (spec PROTOCOL.md sec 8).
//!
//! Direct port of packages/confine/capabilities.fard's operation_allowed().
//! No default-allow: an actor absent from the map, or an operation absent
//! from that actor's explicit list, returns false. Verified against 5 real
//! vectors captured from fardrun v1.7.0.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Actor {
    pub role: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub actors: BTreeMap<String, Actor>,
}

pub fn operation_allowed(capabilities: &Capabilities, actor_id: &str, operation: &str) -> bool {
    match capabilities.actors.get(actor_id) {
        None => false,
        Some(actor) => actor.operations.iter().any(|op| op == operation),
    }
}

pub fn actor_role(capabilities: &Capabilities, actor_id: &str) -> Option<String> {
    capabilities.actors.get(actor_id).map(|a| a.role.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_capabilities() -> Capabilities {
        // Mirrors examples/invoice_config.fard's capabilities.actors exactly.
        let mut actors = BTreeMap::new();
        actors.insert(
            "drafter_1".to_string(),
            Actor {
                role: "drafter".to_string(),
                operations: vec!["read_invoice".to_string(), "create_draft".to_string()],
            },
        );
        actors.insert(
            "approver_1".to_string(),
            Actor {
                role: "approver".to_string(),
                operations: vec![
                    "read_invoice".to_string(),
                    "approve_draft".to_string(),
                    "submit_draft".to_string(),
                ],
            },
        );
        Capabilities { actors }
    }

    // Every value below was captured from a real fardrun v1.7.0 run
    // (examples/gen_label_vectors.fard).

    #[test]
    fn confirmed_operation_allowed_vectors() {
        let c = test_capabilities();
        assert_eq!(operation_allowed(&c, "drafter_1", "read_invoice"), true);
        assert_eq!(operation_allowed(&c, "drafter_1", "create_draft"), true);
        assert_eq!(operation_allowed(&c, "drafter_1", "approve_draft"), false);
        assert_eq!(operation_allowed(&c, "approver_1", "submit_draft"), true);
        assert_eq!(operation_allowed(&c, "nobody", "read_invoice"), false);
    }
}
