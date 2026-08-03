//! Certificate issuance and verification (spec PROTOCOL.md sec 10).
//!
//! Direct port of packages/confine/certificate.fard. Uses the v1-fard MAC
//! construction (tag "confine.certificate.mac.v1", key = raw UTF-8 bytes
//! of the broker_secret string) matching the CURRENT real fardrun
//! behavior -- see hash.rs's certificate_mac_v1_fard for the same
//! double-key-normalization quirk, confirmed empirically in an earlier
//! session. This is a v1-fard artifact per PROTOCOL.md's own versioning
//! rule, not the clean v2 construction used elsewhere in this crate.

use crate::action::Action;
use crate::capabilities::{digest as capability_digest, Capabilities};
use crate::hash::certificate_mac_v1_fard;
use crate::policy::{digest as policy_digest, Obligation, PolicyConfig};
use crate::state::{hash_state, State};
use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Certificate {
    pub prior_state_hash: String,
    pub action_hash: String,
    pub actor_id: String,
    pub policy_hash: String,
    pub capability_hash: String,
    pub nonce: String,
    pub sequence: i64,
    pub obligations: Vec<Obligation>,
    pub mac: String,
}

fn unsigned_value(cert_fields: &Certificate) -> Value {
    let mut map = BTreeMap::new();
    map.insert("t".to_string(), Value::text("transition_certificate"));
    map.insert("version".to_string(), Value::Int(1));
    map.insert("prior_state_hash".to_string(), Value::text(cert_fields.prior_state_hash.clone()));
    map.insert("action_hash".to_string(), Value::text(cert_fields.action_hash.clone()));
    map.insert("actor_id".to_string(), Value::text(cert_fields.actor_id.clone()));
    map.insert("policy_hash".to_string(), Value::text(cert_fields.policy_hash.clone()));
    map.insert("capability_hash".to_string(), Value::text(cert_fields.capability_hash.clone()));
    map.insert("nonce".to_string(), Value::text(cert_fields.nonce.clone()));
    map.insert("sequence".to_string(), Value::Int(cert_fields.sequence));
    map.insert("obligations".to_string(), Value::Array(cert_fields.obligations.iter().map(|o| o.to_value()).collect()));
    Value::Object(map)
}

pub fn issue(
    state: &State,
    action: &Action,
    actor_id: &str,
    capabilities: &Capabilities,
    policy: &PolicyConfig,
    obligations: Vec<Obligation>,
    broker_secret: &str,
) -> Certificate {
    let unsigned = Certificate {
        prior_state_hash: hash_state(state),
        action_hash: action.action_hash(),
        actor_id: actor_id.to_string(),
        policy_hash: policy_digest(policy),
        capability_hash: capability_digest(capabilities),
        nonce: action.nonce().to_string(),
        sequence: state.sequence,
        obligations,
        mac: String::new(), // placeholder, computed below
    };
    let mac = certificate_mac_v1_fard(broker_secret, &unsigned_value(&unsigned));
    Certificate { mac, ..unsigned }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    MissingMac,
    MacMismatch,
    StateMismatch,
    ActionMismatch,
    ActorMismatch,
    PolicyMismatch,
    CapabilityMismatch,
    NonceMismatch,
    SequenceMismatch,
}

impl VerifyError {
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::MissingMac => "CERTIFICATE_MISSING_MAC",
            VerifyError::MacMismatch => "CERTIFICATE_MAC_MISMATCH",
            VerifyError::StateMismatch => "CERTIFICATE_STATE_MISMATCH",
            VerifyError::ActionMismatch => "CERTIFICATE_ACTION_MISMATCH",
            VerifyError::ActorMismatch => "CERTIFICATE_ACTOR_MISMATCH",
            VerifyError::PolicyMismatch => "CERTIFICATE_POLICY_MISMATCH",
            VerifyError::CapabilityMismatch => "CERTIFICATE_CAPABILITY_MISMATCH",
            VerifyError::NonceMismatch => "CERTIFICATE_NONCE_MISMATCH",
            VerifyError::SequenceMismatch => "CERTIFICATE_SEQUENCE_MISMATCH",
        }
    }
}

pub fn verify(
    certificate: &Certificate,
    state: &State,
    action: &Action,
    actor_id: &str,
    capabilities: &Capabilities,
    policy: &PolicyConfig,
    broker_secret: &str,
) -> Result<(), VerifyError> {
    if certificate.mac.is_empty() {
        return Err(VerifyError::MissingMac);
    }
    let expected_mac = certificate_mac_v1_fard(broker_secret, &unsigned_value(certificate));
    if certificate.mac != expected_mac {
        return Err(VerifyError::MacMismatch);
    }
    if certificate.prior_state_hash != hash_state(state) {
        return Err(VerifyError::StateMismatch);
    }
    if certificate.action_hash != action.action_hash() {
        return Err(VerifyError::ActionMismatch);
    }
    if certificate.actor_id != actor_id {
        return Err(VerifyError::ActorMismatch);
    }
    if certificate.policy_hash != policy_digest(policy) {
        return Err(VerifyError::PolicyMismatch);
    }
    if certificate.capability_hash != capability_digest(capabilities) {
        return Err(VerifyError::CapabilityMismatch);
    }
    if certificate.nonce != action.nonce() {
        return Err(VerifyError::NonceMismatch);
    }
    if certificate.sequence != state.sequence {
        return Err(VerifyError::SequenceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::Label;
    use crate::policy::verify as policy_verify;
    use crate::policy::Decision;
    use crate::state::{Counters, Invoice, Thread};
    use crate::capabilities::Actor;
    use std::collections::BTreeSet;

    fn test_policy() -> PolicyConfig {
        let mut approved_recipients = BTreeMap::new();
        approved_recipients.insert("cust_001".to_string(), vec!["billing@example.test".to_string()]);
        approved_recipients.insert("cust_002".to_string(), vec!["accounts@example.test".to_string()]);
        let mut approved_slack_channels = BTreeMap::new();
        approved_slack_channels.insert("channel-finance".to_string(), Label::internal());
        PolicyConfig {
            version: "invoice-policy-v1".into(), min_nonce_length: 12, max_draft_chars: 2000,
            max_total_drafts: 100, max_total_submissions: 20, approver_role: "approver".into(),
            require_separation_of_duties: true, approved_recipients,
            approved_slack_channels, max_total_slack_posts: 10,
        }
    }

    fn test_capabilities() -> Capabilities {
        let mut actors = BTreeMap::new();
        actors.insert("drafter_1".to_string(), Actor { role: "drafter".to_string(), operations: vec!["read_invoice".to_string(), "create_draft".to_string()] });
        actors.insert("approver_1".to_string(), Actor { role: "approver".to_string(), operations: vec!["read_invoice".to_string(), "approve_draft".to_string(), "submit_draft".to_string()] });
        actors.insert("poster_1".to_string(), Actor { role: "poster".to_string(), operations: vec!["post_to_slack".to_string()] });
        let mut operations_registry = BTreeMap::new();
        for op in ["read_invoice", "create_draft", "approve_draft", "submit_draft", "post_to_slack"] {
            operations_registry.insert(op.to_string(), true);
        }
        Capabilities { actors, operations_registry }
    }

    fn initial_state(policy: &PolicyConfig) -> State {
        let mut invoices = BTreeMap::new();
        invoices.insert("inv_001".to_string(), Invoice {
            invoice_id: "inv_001".into(), customer_id: "cust_001".into(), status: "overdue".into(),
            amount_cents: 4200, label: Label::customer("cust_001"),
        });
        invoices.insert("inv_002".to_string(), Invoice {
            invoice_id: "inv_002".into(), customer_id: "cust_002".into(), status: "paid".into(),
            amount_cents: 9900, label: Label::customer("cust_002"),
        });
        let mut threads = BTreeMap::new();
        threads.insert("thread_001".to_string(), Thread { thread_id: "thread_001".into(), customer_id: "cust_001".into() });
        threads.insert("thread_002".to_string(), Thread { thread_id: "thread_002".into(), customer_id: "cust_002".into() });
        State {
            policy_version: policy.version.clone(), sequence: 0, invoices, threads,
            drafts: BTreeMap::new(), approvals: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(), counters: Counters::default(),
            submissions: vec![], slack_posts: vec![],
            previous_receipt_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        }
    }

    fn confirmed_action(s0: &State) -> Action {
        Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "Invoice inv_001 remains overdue. Please review the outstanding balance.".into(),
            body_label: Label::customer("cust_001"),
            nonce: "nonce-exec-0001".into(), expected_state_hash: hash_state(s0),
        }
    }

    // Confirmed against examples/gen_executor_vectors2.fard, fardrun v1.7.0.

    #[test]
    fn confirmed_vector_certificate_mac() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = confirmed_action(&s0);
        let decision = policy_verify(&s0, &action, "drafter_1", &capabilities, &policy);
        let obligations = match decision { Decision::Allow { obligations } => obligations, _ => panic!("expected allow") };
        let secret = "0123456789abcdef0123456789abcdef";
        let cert = issue(&s0, &action, "drafter_1", &capabilities, &policy, obligations, secret);
        assert_eq!(cert.mac, "sha256:bda034f026465709c53c16f02db20824ee3476a95c0f5a76debc184c43619de7");
    }

    #[test]
    fn confirmed_legit_certificate_verifies_ok() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = confirmed_action(&s0);
        let decision = policy_verify(&s0, &action, "drafter_1", &capabilities, &policy);
        let obligations = match decision { Decision::Allow { obligations } => obligations, _ => panic!("expected allow") };
        let secret = "0123456789abcdef0123456789abcdef";
        let cert = issue(&s0, &action, "drafter_1", &capabilities, &policy, obligations, secret);
        assert_eq!(verify(&cert, &s0, &action, "drafter_1", &capabilities, &policy, secret), Ok(()));
    }

    #[test]
    fn confirmed_tampered_certificate_rejected() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = confirmed_action(&s0);
        let decision = policy_verify(&s0, &action, "drafter_1", &capabilities, &policy);
        let obligations = match decision { Decision::Allow { obligations } => obligations, _ => panic!("expected allow") };
        let secret = "0123456789abcdef0123456789abcdef";
        let cert = issue(&s0, &action, "drafter_1", &capabilities, &policy, obligations, secret);
        let tampered = Certificate { actor_id: "attacker".to_string(), ..cert };
        assert_eq!(verify(&tampered, &s0, &action, "attacker", &capabilities, &policy, secret), Err(VerifyError::MacMismatch));
    }
}
