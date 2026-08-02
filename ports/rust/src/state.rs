//! Committed state model (spec PROTOCOL.md sec 9, state shape).
//!
//! Mirrors packages/confine/state.fard's initial() record shape closely
//! enough to support policy.verify(). Not yet a full port of state.fard's
//! hash_state()/nonce/draft/approval accessor functions -- those are added
//! when the executor layer (spec sec 10-11) is ported.

use crate::labels::Label;
use crate::value::Value;
use crate::hash::tagged_digest;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Invoice {
    pub invoice_id: String,
    pub customer_id: String,
    pub status: String,
    pub amount_cents: i64,
    pub label: Label,
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub thread_id: String,
    pub customer_id: String,
}

#[derive(Debug, Clone)]
pub struct Delivery {
    pub email_submitted: bool,
    pub email_recipient: Option<String>,
    pub slack_posted_channels: BTreeSet<String>,
}

impl Delivery {
    pub fn new() -> Delivery {
        Delivery { email_submitted: false, email_recipient: None, slack_posted_channels: BTreeSet::new() }
    }
}

#[derive(Debug, Clone)]
pub struct Draft {
    pub draft_hash: String,
    pub thread_id: String,
    pub invoice_id: String,
    pub customer_id: String,
    pub body: String,
    pub body_label: Label,
    pub created_by: String,
    pub deliveries: Delivery,
}

#[derive(Debug, Clone)]
pub struct Approval {
    pub draft_hash: String,
    pub approver_id: String,
    pub sequence: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Counters {
    pub drafted_total: i64,
    pub approved_total: i64,
    pub submitted_total: i64,
    pub slack_posted_total: i64,
}

#[derive(Debug, Clone)]
pub struct State {
    pub policy_version: String,
    pub sequence: i64,
    pub invoices: BTreeMap<String, Invoice>,
    pub threads: BTreeMap<String, Thread>,
    pub drafts: BTreeMap<String, Draft>,
    pub approvals: BTreeMap<String, Approval>,
    pub consumed_nonces: BTreeSet<String>,
    pub counters: Counters,
    pub submissions: Vec<Value>,
    pub slack_posts: Vec<Value>,
    pub previous_receipt_hash: String,
}

pub fn get_invoice<'a>(state: &'a State, invoice_id: &str) -> Option<&'a Invoice> {
    state.invoices.get(invoice_id)
}

pub fn get_thread<'a>(state: &'a State, thread_id: &str) -> Option<&'a Thread> {
    state.threads.get(thread_id)
}

pub fn get_draft<'a>(state: &'a State, draft_hash: &str) -> Option<&'a Draft> {
    state.drafts.get(draft_hash)
}

pub fn get_approval<'a>(state: &'a State, draft_hash: &str) -> Option<&'a Approval> {
    state.approvals.get(draft_hash)
}

pub fn nonce_consumed(state: &State, nonce: &str) -> bool {
    state.consumed_nonces.contains(nonce)
}


// --- Canonical value conversions (spec PROTOCOL.md sec 3, sec 9 state shape) ---
// Every field name and nesting mirrors the real state record shape,
// confirmed against fardrun v1.7.0's canonical.canonical_text(initial_state)
// -- see examples/gen_hash_state_vectors.fard. Only the empty-state shape
// (no drafts/approvals/submissions) has been vector-confirmed so far;
// non-empty Draft/Approval to_value() below are transcribed directly from
// the known real draft/approval record shapes seen elsewhere in this
// session's fardrun output, but not yet independently re-verified via a
// dedicated non-empty-state hash vector.

impl Invoice {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("invoice_id", Value::text(self.invoice_id.clone())),
            ("customer_id", Value::text(self.customer_id.clone())),
            ("status", Value::text(self.status.clone())),
            ("amount_cents", Value::Int(self.amount_cents)),
            ("label", self.label.to_value()),
        ])
    }
}

impl Thread {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("thread_id", Value::text(self.thread_id.clone())),
            ("customer_id", Value::text(self.customer_id.clone())),
        ])
    }
}

impl Delivery {
    pub fn to_value(&self) -> Value {
        let email = Value::object(vec![
            ("submitted", Value::Bool(self.email_submitted)),
            ("recipient", match &self.email_recipient { Some(r) => Value::text(r.clone()), None => Value::Null }),
        ]);
        let mut slack_map = std::collections::BTreeMap::new();
        for ch in &self.slack_posted_channels {
            slack_map.insert(ch.clone(), Value::Bool(true));
        }
        Value::object(vec![
            ("email", email),
            ("slack", Value::Object(slack_map)),
        ])
    }
}

impl Draft {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("body", Value::text(self.body.clone())),
            ("body_label", self.body_label.to_value()),
            ("created_by", Value::text(self.created_by.clone())),
            ("customer_id", Value::text(self.customer_id.clone())),
            ("deliveries", self.deliveries.to_value()),
            ("draft_hash", Value::text(self.draft_hash.clone())),
            ("invoice_id", Value::text(self.invoice_id.clone())),
            ("thread_id", Value::text(self.thread_id.clone())),
        ])
    }
}

impl Approval {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("approver_id", Value::text(self.approver_id.clone())),
            ("draft_hash", Value::text(self.draft_hash.clone())),
            ("sequence", Value::Int(self.sequence)),
        ])
    }
}

impl Counters {
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("approved_total", Value::Int(self.approved_total)),
            ("drafted_total", Value::Int(self.drafted_total)),
            ("slack_posted_total", Value::Int(self.slack_posted_total)),
            ("submitted_total", Value::Int(self.submitted_total)),
        ])
    }
}

impl State {
    /// Value representation with previous_receipt_hash OMITTED entirely
    /// (not set to null) -- matches rec.remove(state, "previous_receipt_hash")
    /// in state.fard's hash_state(), confirmed against real canonical_text
    /// output showing the key genuinely absent, not null, when removed.
    pub fn to_value_for_hashing(&self) -> Value {
        let mut invoices = BTreeMap::new();
        for (k, v) in &self.invoices { invoices.insert(k.clone(), v.to_value()); }
        let mut threads = BTreeMap::new();
        for (k, v) in &self.threads { threads.insert(k.clone(), v.to_value()); }
        let mut drafts = BTreeMap::new();
        for (k, v) in &self.drafts { drafts.insert(k.clone(), v.to_value()); }
        let mut approvals = BTreeMap::new();
        for (k, v) in &self.approvals { approvals.insert(k.clone(), v.to_value()); }
        let mut consumed_nonces = BTreeMap::new();
        for n in &self.consumed_nonces { consumed_nonces.insert(n.clone(), Value::Bool(true)); }

        Value::object(vec![
            ("policy_version", Value::text(self.policy_version.clone())),
            ("sequence", Value::Int(self.sequence)),
            ("invoices", Value::Object(invoices)),
            ("threads", Value::Object(threads)),
            ("drafts", Value::Object(drafts)),
            ("approvals", Value::Object(approvals)),
            ("consumed_nonces", Value::Object(consumed_nonces)),
            ("counters", self.counters.to_value()),
            ("submissions", Value::Array(self.submissions.clone())),
            ("slack_posts", Value::Array(self.slack_posts.clone())),
        ])
    }
}

/// Direct port of state.fard's hash_state(). Confirmed against a real
/// fardrun v1.7.0 vector for the empty-invoice-config initial state
/// (examples/gen_hash_state_vectors.fard) -- see tests below.
pub fn hash_state(state: &State) -> String {
    tagged_digest("confine.state.v1", &state.to_value_for_hashing())
}

#[cfg(test)]
mod hash_state_tests {
    use super::*;
    use crate::labels::Label;

    fn confirmed_initial_state() -> State {
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
            policy_version: "invoice-policy-v1".into(), sequence: 0, invoices, threads,
            drafts: BTreeMap::new(), approvals: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(), counters: Counters::default(),
            submissions: vec![], slack_posts: vec![],
            previous_receipt_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        }
    }

    #[test]
    fn confirmed_vector_initial_state_hash() {
        let state = confirmed_initial_state();
        assert_eq!(
            hash_state(&state),
            "sha256:20db1ed809ccec07704888c74ebae6d0ca9ee17119f6d46e03e2e0de88fa1576"
        );
    }
}
