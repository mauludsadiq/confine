//! Executor conformance (spec PROTOCOL.md sec 11) -- the normative
//! invariant this entire project is built around.
//!
//! A conforming executor MUST independently invoke the complete policy
//! decision procedure over the exact current state, canonical action,
//! actor identity, capability set, and policy object, immediately before
//! committing any effect. A certificate, its obligations, or a previously
//! computed policy result MUST NOT substitute for this invocation.
//!
//! Direct port of packages/confine/executor.fard's execute_exact(). Every
//! branch traces to a real decision captured via
//! examples/gen_executor_vectors2.fard, fardrun v1.7.0 -- including the
//! critical adversarial case: a certificate whose obligations are
//! internally consistent with a forged action, but where the action
//! itself violates policy. An obligations-only check cannot catch this;
//! only independently rerunning the full policy kernel can.

use crate::action::Action;
use crate::capabilities::Capabilities;
use crate::certificate::{verify as certificate_verify, Certificate};
use crate::policy::{verify as policy_verify, Decision, PolicyConfig};
use crate::state::{nonce_consumed, State};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    CertificateInvalid(&'static str),
    ExecutorPolicyDenied(String),
    CertificateObligationMismatch,
    NonceReplayAtExecutor,
}

impl ExecuteError {
    pub fn code(&self) -> String {
        match self {
            ExecuteError::CertificateInvalid(c) => c.to_string(),
            ExecuteError::ExecutorPolicyDenied(_) => "EXECUTOR_POLICY_DENIED".to_string(),
            ExecuteError::CertificateObligationMismatch => "CERTIFICATE_OBLIGATION_MISMATCH".to_string(),
            ExecuteError::NonceReplayAtExecutor => "NONCE_REPLAY_AT_EXECUTOR".to_string(),
        }
    }
}

/// The normative conformance check. This is not a helper -- this function
/// IS the security boundary. Called by execute_exact() before any commit.
pub fn execute_exact(
    state: &State,
    action: &Action,
    actor_id: &str,
    capabilities: &Capabilities,
    policy: &PolicyConfig,
    certificate: &Certificate,
    broker_secret: &str,
) -> Result<Decision, ExecuteError> {
    // Step 1: certificate must verify (MAC, all bound-field equality checks).
    certificate_verify(certificate, state, action, actor_id, capabilities, policy, broker_secret)
        .map_err(|e| ExecuteError::CertificateInvalid(e.code()))?;

    // Step 2: INDEPENDENTLY rerun the full policy kernel. This is the
    // invariant. Do not substitute certificate.obligations or any prior
    // result for this call.
    let decision = policy_verify(state, action, actor_id, capabilities, policy);
    let obligations = match decision {
        Decision::Deny { code } => return Err(ExecuteError::ExecutorPolicyDenied(code)),
        Decision::Allow { ref obligations } => obligations.clone(),
    };

    // Step 3: certificate's claimed obligations must exactly match what
    // policy just independently derived.
    let cert_obligations_value = crate::value::Value::Array(certificate.obligations.iter().map(|o| o.to_value()).collect());
    let real_obligations_value = crate::value::Value::Array(obligations.iter().map(|o| o.to_value()).collect());
    if crate::canonical::encode(&cert_obligations_value) != crate::canonical::encode(&real_obligations_value) {
        return Err(ExecuteError::CertificateObligationMismatch);
    }

    // Step 4: nonce must not already be consumed in this exact state.
    if nonce_consumed(state, action.nonce()) {
        return Err(ExecuteError::NonceReplayAtExecutor);
    }

    Ok(Decision::Allow { obligations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::issue;
    use crate::labels::Label;
    use crate::policy::Obligation;
    use crate::state::{Counters, Invoice, Thread};
    use crate::capabilities::Actor;
    use std::collections::{BTreeMap, BTreeSet};

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

    // Confirmed against examples/gen_executor_vectors2.fard, fardrun v1.7.0.

    #[test]
    fn confirmed_legit_execution_succeeds() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "Invoice inv_001 remains overdue. Please review the outstanding balance.".into(),
            body_label: Label::customer("cust_001"),
            nonce: "nonce-exec-0001".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let decision = policy_verify(&s0, &action, "drafter_1", &capabilities, &policy);
        let obligations = match decision { Decision::Allow { obligations } => obligations, _ => panic!("expected allow") };
        let secret = "0123456789abcdef0123456789abcdef";
        let cert = issue(&s0, &action, "drafter_1", &capabilities, &policy, obligations, secret);

        let result = execute_exact(&s0, &action, "drafter_1", &capabilities, &policy, &cert, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn confirmed_forged_action_rejected_by_independent_policy_rerun() {
        // The core invariant test: obligations are internally consistent
        // with the forged action, so an obligations-only check would NOT
        // catch this. Only independently rerunning policy.verify() does.
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let bad_action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "test".into(), body_label: Label::customer("cust_999"),
            nonce: "nonce-exec-0002".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let bad_obligations = vec![
            Obligation { t: "bind_customer".into(), data: [("customer_id".to_string(), "cust_001".to_string())].into(), label: None },
            Obligation { t: "body_label".into(), data: BTreeMap::new(), label: Some(Label::customer("cust_999")) },
        ];
        let secret = "0123456789abcdef0123456789abcdef";
        let bad_cert = issue(&s0, &bad_action, "drafter_1", &capabilities, &policy, bad_obligations, secret);

        let result = execute_exact(&s0, &bad_action, "drafter_1", &capabilities, &policy, &bad_cert, secret);
        match result {
            Err(ExecuteError::ExecutorPolicyDenied(code)) => assert_eq!(code, "IFC_INVOICE_TO_BODY"),
            other => panic!("expected ExecutorPolicyDenied(IFC_INVOICE_TO_BODY), got {:?}", other),
        }
    }

    #[test]
    fn confirmed_obligation_mismatch_rejected() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "Invoice inv_001 remains overdue. Please review the outstanding balance.".into(),
            body_label: Label::customer("cust_001"),
            nonce: "nonce-exec-0001".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let mismatched_obligations = vec![
            Obligation { t: "bind_customer".into(), data: [("customer_id".to_string(), "cust_001".to_string())].into(), label: None },
            Obligation { t: "body_label".into(), data: BTreeMap::new(), label: Some(Label::customer("cust_002")) },
        ];
        let secret = "0123456789abcdef0123456789abcdef";
        let mismatch_cert = issue(&s0, &action, "drafter_1", &capabilities, &policy, mismatched_obligations, secret);

        let result = execute_exact(&s0, &action, "drafter_1", &capabilities, &policy, &mismatch_cert, secret);
        assert_eq!(result, Err(ExecuteError::CertificateObligationMismatch));
    }
}
