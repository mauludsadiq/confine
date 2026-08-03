//! Capability model (spec PROTOCOL.md sec 8).
//!
//! Direct port of packages/confine/capabilities.fard's operation_allowed().
//! No default-allow: an actor absent from the map, or an operation absent
//! from that actor's explicit list, returns false. Verified against 5 real
//! vectors captured from fardrun v1.7.0.

use crate::value::Value;
use crate::hash::tagged_digest;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Actor {
    pub role: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub actors: BTreeMap<String, Actor>,
    /// Declarative registry of known operation names -> true. Confirmed
    /// via fardrun to be a real field included in capability_hash, even
    /// though operation_allowed() never reads it (it only reads
    /// actors[actor_id].operations). Must be populated correctly or
    /// capability_hash will silently not match.
    pub operations_registry: BTreeMap<String, bool>,
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
        Capabilities { actors, operations_registry: BTreeMap::new() }
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


impl Actor {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("role", Value::text(self.role.clone())),
            ("operations", Value::Array(self.operations.iter().map(|o| Value::text(o.clone())).collect())),
        ])
    }
}

impl Capabilities {
    pub fn to_value(&self) -> Value {
        let mut actors = std::collections::BTreeMap::new();
        for (k, v) in &self.actors { actors.insert(k.clone(), v.to_value()); }
        let mut operations = std::collections::BTreeMap::new();
        for (k, v) in &self.operations_registry { operations.insert(k.clone(), Value::Bool(*v)); }
        Value::object(vec![
            ("actors", Value::Object(actors)),
            ("operations", Value::Object(operations)),
        ])
    }
}

pub fn digest(capabilities: &Capabilities) -> String {
    tagged_digest("confine.capabilities.v1", &capabilities.to_value())
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn confirmed_vector_capability_hash() {
        let mut actors = BTreeMap::new();
        actors.insert("drafter_1".to_string(), Actor { role: "drafter".to_string(), operations: vec!["read_invoice".to_string(), "create_draft".to_string()] });
        actors.insert("approver_1".to_string(), Actor { role: "approver".to_string(), operations: vec!["read_invoice".to_string(), "approve_draft".to_string(), "submit_draft".to_string()] });
        actors.insert("poster_1".to_string(), Actor { role: "poster".to_string(), operations: vec!["post_to_slack".to_string()] });
        let mut operations_registry = BTreeMap::new();
        for op in ["read_invoice", "create_draft", "approve_draft", "submit_draft", "post_to_slack"] {
            operations_registry.insert(op.to_string(), true);
        }
        let capabilities = Capabilities { actors, operations_registry };
        assert_eq!(digest(&capabilities), "sha256:07ffa73a9a69e9d9dcd9850a8d6ed5cdbc4dfff13b7fdbdb880612fa1283ffcb");
    }
}
