//! Deterministic policy decision procedure (spec PROTOCOL.md sec 9).
//!
//! Direct port of packages/confine/policy.fard. Every branch and check
//! order traces to a specific line in that file. Verified against 6 real
//! decisions captured from fardrun v1.7.0 by walking an actual
//! create_draft -> approve_draft -> submit_draft sequence plus three
//! adversarial deny paths (examples/gen_policy_vectors.fard) -- see tests.
//!
//! obligations_for_read_invoice and obligations_for_post_to_slack are
//! transcribed directly from source but NOT yet independently verified
//! against a captured vector (only create_draft/approve_draft/submit_draft
//! decisions were captured). Treat those two as unverified until a
//! corresponding vector is generated.

use crate::action::Action;
use crate::capabilities::{operation_allowed, actor_role, Capabilities};
use crate::labels::{flows_to, Label};
use crate::state::{get_approval, get_draft, get_invoice, get_thread, nonce_consumed, State};
use std::collections::BTreeMap;

impl Obligation {
    pub fn to_value(&self) -> crate::value::Value {
        use crate::value::Value;
        let mut map = std::collections::BTreeMap::new();
        map.insert("t".to_string(), Value::text(self.t.clone()));
        for (k, v) in &self.data {
            map.insert(k.clone(), Value::text(v.clone()));
        }
        if let Some(label) = &self.label {
            map.insert("label".to_string(), label.to_value());
        }
        Value::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Obligation {
    pub t: String,
    pub data: BTreeMap<String, String>,
    pub label: Option<Label>,
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub version: String,
    pub min_nonce_length: usize,
    pub max_draft_chars: usize,
    pub max_total_drafts: i64,
    pub max_total_submissions: i64,
    pub approver_role: String,
    pub require_separation_of_duties: bool,
    pub approved_recipients: BTreeMap<String, Vec<String>>,
    pub approved_slack_channels: BTreeMap<String, Label>,
    pub max_total_slack_posts: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow { obligations: Vec<Obligation> },
    Deny { code: String },
}

fn deny(code: &str) -> Decision {
    Decision::Deny { code: code.to_string() }
}

fn allow(obligations: Vec<Obligation>) -> Decision {
    Decision::Allow { obligations }
}

pub fn obligations_for_create_draft(customer_id: &str, body_label: &Label) -> Vec<Obligation> {
    vec![
        Obligation { t: "bind_customer".into(), data: [("customer_id".to_string(), customer_id.to_string())].into(), label: None },
        Obligation { t: "body_label".into(), data: BTreeMap::new(), label: Some(body_label.clone()) },
    ]
}

pub fn obligations_for_approve_draft(draft_hash: &str) -> Vec<Obligation> {
    vec![Obligation { t: "approve_exact_hash".into(), data: [("draft_hash".to_string(), draft_hash.to_string())].into(), label: None }]
}

pub fn obligations_for_submit_draft(draft_hash: &str, recipient: &str) -> Vec<Obligation> {
    vec![
        Obligation { t: "submit_exact_hash".into(), data: [("draft_hash".to_string(), draft_hash.to_string())].into(), label: None },
        Obligation { t: "recipient".into(), data: [("recipient".to_string(), recipient.to_string())].into(), label: None },
    ]
}

fn common_checks(state: &State, action: &Action, actor_id: &str, capabilities: &Capabilities, policy: &PolicyConfig) -> Option<Decision> {
    if state.policy_version != policy.version {
        return Some(deny("POLICY_VERSION_MISMATCH"));
    }
    if action.expected_state_hash() != crate::state::hash_state(state) {
        return Some(deny("STALE_STATE"));
    }
    if nonce_consumed(state, action.nonce()) {
        return Some(deny("NONCE_REPLAY"));
    }
    if action.nonce().len() < policy.min_nonce_length {
        return Some(deny("NONCE_TOO_SHORT"));
    }
    if !operation_allowed(capabilities, actor_id, action.type_tag()) {
        return Some(deny("CAPABILITY_DENIED"));
    }
    None
}

pub fn verify(state: &State, action: &Action, actor_id: &str, capabilities: &Capabilities, policy: &PolicyConfig) -> Decision {
    if let Some(d) = common_checks(state, action, actor_id, capabilities, policy) {
        return d;
    }

    match action {
        Action::ReadInvoice { invoice_id, .. } => {
            match get_invoice(state, invoice_id) {
                None => deny("INVOICE_NOT_FOUND"),
                Some(invoice) => allow(vec![Obligation { t: "result_label".into(), data: BTreeMap::new(), label: Some(invoice.label.clone()) }]),
            }
        }
        Action::CreateDraft { thread_id, invoice_id, customer_id, body, body_label, .. } => {
            let invoice = match get_invoice(state, invoice_id) { None => return deny("INVOICE_NOT_FOUND"), Some(i) => i };
            let thread = match get_thread(state, thread_id) { None => return deny("THREAD_NOT_FOUND"), Some(t) => t };
            if &invoice.customer_id != customer_id {
                return deny("INVOICE_CUSTOMER_MISMATCH");
            }
            if &thread.customer_id != customer_id {
                return deny("THREAD_CUSTOMER_MISMATCH");
            }
            if !flows_to(&invoice.label, body_label) {
                return deny("IFC_INVOICE_TO_BODY");
            }
            if body_label.kind != "customer" || &body_label.owner != customer_id {
                return deny("BODY_LABEL_OWNER_MISMATCH");
            }
            if body.is_empty() {
                return deny("EMPTY_DRAFT");
            }
            if body.len() > policy.max_draft_chars {
                return deny("DRAFT_TOO_LARGE");
            }
            if state.counters.drafted_total >= policy.max_total_drafts {
                return deny("DRAFT_QUOTA");
            }
            allow(obligations_for_create_draft(customer_id, body_label))
        }
        Action::ApproveDraft { draft_hash, approver_id, .. } => {
            let draft = match get_draft(state, draft_hash) { None => return deny("DRAFT_NOT_FOUND"), Some(d) => d };
            let role = actor_role(capabilities, actor_id);
            if role.as_deref() != Some(policy.approver_role.as_str()) {
                return deny("APPROVER_ROLE_REQUIRED");
            }
            if actor_id != approver_id {
                return deny("APPROVER_ID_MISMATCH");
            }
            if &draft.created_by == actor_id && policy.require_separation_of_duties {
                return deny("SEPARATION_OF_DUTIES");
            }
            if get_approval(state, draft_hash).is_some() {
                return deny("ALREADY_APPROVED");
            }
            allow(obligations_for_approve_draft(draft_hash))
        }
        Action::SubmitDraft { draft_hash, recipient, recipient_label, .. } => {
            let draft = match get_draft(state, draft_hash) { None => return deny("DRAFT_NOT_FOUND"), Some(d) => d };
            if get_approval(state, draft_hash).is_none() {
                return deny("APPROVAL_REQUIRED");
            }
            if draft.deliveries.email_submitted {
                return deny("ALREADY_SUBMITTED");
            }
            let recipients_ok = policy.approved_recipients.get(&draft.customer_id).map(|list| list.contains(recipient)).unwrap_or(false);
            if !recipients_ok {
                return deny("RECIPIENT_NOT_APPROVED");
            }
            if recipient_label.kind != "customer" || recipient_label.owner != draft.customer_id {
                return deny("RECIPIENT_LABEL_OWNER_MISMATCH");
            }
            if !flows_to(&draft.body_label, recipient_label) {
                return deny("IFC_BODY_TO_RECIPIENT");
            }
            if state.counters.submitted_total >= policy.max_total_submissions {
                return deny("SUBMISSION_QUOTA");
            }
            allow(obligations_for_submit_draft(draft_hash, recipient))
        }
        Action::PostToSlack { draft_hash, channel_id, channel_label, .. } => {
            let draft = match get_draft(state, draft_hash) { None => return deny("DRAFT_NOT_FOUND"), Some(d) => d };
            if get_approval(state, draft_hash).is_none() {
                return deny("APPROVAL_REQUIRED");
            }
            let channel = match policy.approved_slack_channels.get(channel_id) { None => return deny("CHANNEL_NOT_FOUND"), Some(c) => c };
            if channel_label != channel {
                return deny("CHANNEL_LABEL_MISMATCH");
            }
            if !flows_to(&draft.body_label, channel) {
                return deny("IFC_BODY_TO_CHANNEL");
            }
            if draft.deliveries.slack_posted_channels.contains(channel_id) {
                return deny("ALREADY_POSTED");
            }
            if state.counters.slack_posted_total >= policy.max_total_slack_posts {
                return deny("SLACK_QUOTA");
            }
            allow(vec![
                Obligation { t: "post_exact_hash".into(), data: [("draft_hash".to_string(), draft_hash.clone())].into(), label: None },
                Obligation { t: "channel".into(), data: [("channel_id".to_string(), channel_id.clone())].into(), label: None },
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Actor;
    use crate::state::{Approval, Counters, Delivery, Draft, Invoice, Thread};
    use std::collections::BTreeSet;

    fn test_policy() -> PolicyConfig {
        let mut approved_recipients = BTreeMap::new();
        approved_recipients.insert("cust_001".to_string(), vec!["billing@example.test".to_string()]);
        PolicyConfig {
            version: "invoice-policy-v1".into(),
            min_nonce_length: 12,
            max_draft_chars: 2000,
            max_total_drafts: 100,
            max_total_submissions: 20,
            approver_role: "approver".into(),
            require_separation_of_duties: true,
            approved_recipients,
            approved_slack_channels: BTreeMap::new(),
            max_total_slack_posts: 10,
        }
    }

    fn test_capabilities() -> Capabilities {
        let mut actors = BTreeMap::new();
        actors.insert("drafter_1".to_string(), Actor { role: "drafter".to_string(), operations: vec!["read_invoice".to_string(), "create_draft".to_string()] });
        actors.insert("approver_1".to_string(), Actor { role: "approver".to_string(), operations: vec!["read_invoice".to_string(), "approve_draft".to_string(), "submit_draft".to_string()] });
        Capabilities { actors, operations_registry: std::collections::BTreeMap::new() }
    }

    fn initial_state(policy: &PolicyConfig) -> State {
        let mut invoices = BTreeMap::new();
        invoices.insert("inv_001".to_string(), Invoice {
            invoice_id: "inv_001".into(), customer_id: "cust_001".into(), status: "overdue".into(),
            amount_cents: 4200, label: Label::customer("cust_001"),
        });
        let mut threads = BTreeMap::new();
        threads.insert("thread_001".to_string(), Thread { thread_id: "thread_001".into(), customer_id: "cust_001".into() });
        State {
            policy_version: policy.version.clone(), sequence: 0, invoices, threads,
            drafts: BTreeMap::new(), approvals: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(), counters: Counters::default(),
            submissions: vec![], slack_posts: vec![],
            previous_receipt_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        }
    }

    // Every assertion below traces to a real decision captured via
    // examples/gen_policy_vectors.fard against fardrun v1.7.0.

    #[test]
    fn confirmed_create_draft_allow() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "Invoice inv_001 remains overdue. Please review the outstanding balance.".into(),
            body_label: Label::customer("cust_001"),
            nonce: "nonce-vec-0001".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let decision = verify(&s0, &action, "drafter_1", &capabilities, &policy);
        match decision {
            Decision::Allow { obligations } => {
                assert_eq!(obligations.len(), 2);
                assert_eq!(obligations[0].t, "bind_customer");
                assert_eq!(obligations[1].t, "body_label");
            }
            Decision::Deny { code } => panic!("expected allow, got deny: {}", code),
        }
    }

    #[test]
    fn confirmed_deny_stale_state() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = Action::ReadInvoice {
            invoice_id: "inv_001".into(),
            nonce: "nonce-vec-0006".into(),
            // Deliberately wrong: a hash that isn't s0's real hash. In the
            // real captured vector this was expected_state_hash computed
            // against a DIFFERENT prior state (s1), presented against s1
            // in fardrun. Here we simplify to any non-matching hash string,
            // since the point is proving the mismatch check fires at all.
            expected_state_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let decision = verify(&s0, &action, "drafter_1", &capabilities, &policy);
        match decision {
            Decision::Deny { code } => assert_eq!(code, "STALE_STATE"),
            Decision::Allow { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn confirmed_deny_capability() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        // drafter_1 lacks approve_draft capability
        let action = Action::ApproveDraft {
            draft_hash: "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba".into(),
            approver_id: "drafter_1".into(), nonce: "nonce-vec-0004".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let decision = verify(&s0, &action, "drafter_1", &capabilities, &policy);
        match decision {
            Decision::Deny { code } => assert_eq!(code, "CAPABILITY_DENIED"),
            Decision::Allow { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn confirmed_deny_ifc_invoice_to_body() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "test".into(), body_label: Label::customer("cust_999"),
            nonce: "nonce-vec-0005".into(), expected_state_hash: crate::state::hash_state(&s0),
        };
        let decision = verify(&s0, &action, "drafter_1", &capabilities, &policy);
        match decision {
            Decision::Deny { code } => assert_eq!(code, "IFC_INVOICE_TO_BODY"),
            Decision::Allow { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn confirmed_approve_and_submit_allow_full_sequence() {
        let policy = test_policy();
        let capabilities = test_capabilities();
        let s0 = initial_state(&policy);
        let draft_hash = "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba".to_string();

        let mut s1 = s0.clone();
        s1.drafts.insert(draft_hash.clone(), Draft {
            draft_hash: draft_hash.clone(), thread_id: "thread_001".into(), invoice_id: "inv_001".into(),
            customer_id: "cust_001".into(), body: "x".into(), body_label: Label::customer("cust_001"),
            created_by: "drafter_1".into(), deliveries: Delivery::new(),
        });

        let approve_action = Action::ApproveDraft {
            draft_hash: draft_hash.clone(), approver_id: "approver_1".into(),
            nonce: "nonce-vec-0002".into(), expected_state_hash: crate::state::hash_state(&s1),
        };
        let approve_decision = verify(&s1, &approve_action, "approver_1", &capabilities, &policy);
        match approve_decision {
            Decision::Allow { obligations } => assert_eq!(obligations[0].t, "approve_exact_hash"),
            Decision::Deny { code } => panic!("expected allow, got: {}", code),
        }

        s1.approvals.insert(draft_hash.clone(), Approval { draft_hash: draft_hash.clone(), approver_id: "approver_1".into(), sequence: 1 });

        let submit_action = Action::SubmitDraft {
            draft_hash: draft_hash.clone(), recipient: "billing@example.test".into(),
            recipient_label: Label::customer("cust_001"),
            nonce: "nonce-vec-0003".into(), expected_state_hash: crate::state::hash_state(&s1),
        };
        let submit_decision = verify(&s1, &submit_action, "approver_1", &capabilities, &policy);
        match submit_decision {
            Decision::Allow { obligations } => {
                assert_eq!(obligations[0].t, "submit_exact_hash");
                assert_eq!(obligations[1].t, "recipient");
            }
            Decision::Deny { code } => panic!("expected allow, got: {}", code),
        }
    }
}

// --- Canonical value conversion and digest (spec PROTOCOL.md sec 9) ---
// Confirmed against real fardrun output (examples/gen_policy_canonical.fard)
// -- note approved_slack_channels nests each channel as { label: {...} },
// not the label directly, which was NOT obvious from source alone.

impl PolicyConfig {
    pub fn to_value(&self) -> crate::value::Value {
        use crate::value::Value;
        let mut approved_recipients = std::collections::BTreeMap::new();
        for (k, v) in &self.approved_recipients {
            approved_recipients.insert(k.clone(), Value::Array(v.iter().map(|r| Value::text(r.clone())).collect()));
        }
        let mut approved_slack_channels = std::collections::BTreeMap::new();
        for (k, label) in &self.approved_slack_channels {
            approved_slack_channels.insert(k.clone(), Value::object(vec![("label", label.to_value())]));
        }
        Value::object(vec![
            ("approved_recipients", Value::Object(approved_recipients)),
            ("approved_slack_channels", Value::Object(approved_slack_channels)),
            ("approver_role", Value::text(self.approver_role.clone())),
            ("max_draft_chars", Value::Int(self.max_draft_chars as i64)),
            ("max_total_drafts", Value::Int(self.max_total_drafts)),
            ("max_total_slack_posts", Value::Int(self.max_total_slack_posts)),
            ("max_total_submissions", Value::Int(self.max_total_submissions)),
            ("min_nonce_length", Value::Int(self.min_nonce_length as i64)),
            ("require_separation_of_duties", Value::Bool(self.require_separation_of_duties)),
            ("version", Value::text(self.version.clone())),
        ])
    }
}

pub fn digest(policy: &PolicyConfig) -> String {
    crate::hash::tagged_digest("confine.policy.v1", &policy.to_value())
}

#[cfg(test)]
mod digest_tests {
    use super::*;
    use crate::labels::Label;

    #[test]
    fn confirmed_vector_policy_hash() {
        let mut approved_recipients = BTreeMap::new();
        approved_recipients.insert("cust_001".to_string(), vec!["billing@example.test".to_string()]);
        approved_recipients.insert("cust_002".to_string(), vec!["accounts@example.test".to_string()]);
        let mut approved_slack_channels = BTreeMap::new();
        approved_slack_channels.insert("channel-finance".to_string(), Label::internal());
        let policy = PolicyConfig {
            version: "invoice-policy-v1".into(), min_nonce_length: 12, max_draft_chars: 2000,
            max_total_drafts: 100, max_total_submissions: 20, approver_role: "approver".into(),
            require_separation_of_duties: true, approved_recipients, approved_slack_channels,
            max_total_slack_posts: 10,
        };
        assert_eq!(digest(&policy), "sha256:64d54739cc1ce345d4f9ad87efdcf818612de708830ab2c9ed9847c0b9eb7c5e");
    }
}


#[cfg(test)]
mod obligation_diagnostic_tests {
    use super::*;
    use crate::labels::Label;
    use crate::canonical::encode;

    #[test]
    fn diagnostic_confirmed_create_draft_obligations_canonical() {
        let obligations = obligations_for_create_draft("cust_001", &Label::customer("cust_001"));
        let value = crate::value::Value::Array(obligations.iter().map(|o| o.to_value()).collect());
        let expected = "[{\"customer_id\":\"cust_001\",\"t\":\"bind_customer\"},{\"label\":{\"compartments\":[\"customer_data\"],\"kind\":\"customer\",\"owner\":\"cust_001\"},\"t\":\"body_label\"}]";
        assert_eq!(encode(&value), expected);
    }
}
