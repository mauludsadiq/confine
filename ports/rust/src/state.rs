//! Committed state model (spec PROTOCOL.md sec 9, state shape).
//!
//! Mirrors packages/confine/state.fard's initial() record shape closely
//! enough to support policy.verify(). Not yet a full port of state.fard's
//! hash_state()/nonce/draft/approval accessor functions -- those are added
//! when the executor layer (spec sec 10-11) is ported.

use crate::labels::Label;
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
