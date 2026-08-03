//! Closed action algebra (spec PROTOCOL.md sec 6).

use crate::labels::Label;
use crate::value::Value;
use crate::hash::tagged_digest;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum Action {
    ReadInvoice {
        invoice_id: String,
        nonce: String,
        expected_state_hash: String,
    },
    CreateDraft {
        thread_id: String,
        invoice_id: String,
        customer_id: String,
        body: String,
        body_label: Label,
        nonce: String,
        expected_state_hash: String,
    },
    ApproveDraft {
        draft_hash: String,
        approver_id: String,
        nonce: String,
        expected_state_hash: String,
    },
    SubmitDraft {
        draft_hash: String,
        recipient: String,
        recipient_label: Label,
        nonce: String,
        expected_state_hash: String,
    },
    PostToSlack {
        draft_hash: String,
        channel_id: String,
        channel_label: Label,
        nonce: String,
        expected_state_hash: String,
    },
}

impl Action {
    pub fn nonce(&self) -> &str {
        match self {
            Action::ReadInvoice { nonce, .. } => nonce,
            Action::CreateDraft { nonce, .. } => nonce,
            Action::ApproveDraft { nonce, .. } => nonce,
            Action::SubmitDraft { nonce, .. } => nonce,
            Action::PostToSlack { nonce, .. } => nonce,
        }
    }

    pub fn expected_state_hash(&self) -> &str {
        match self {
            Action::ReadInvoice { expected_state_hash, .. } => expected_state_hash,
            Action::CreateDraft { expected_state_hash, .. } => expected_state_hash,
            Action::ApproveDraft { expected_state_hash, .. } => expected_state_hash,
            Action::SubmitDraft { expected_state_hash, .. } => expected_state_hash,
            Action::PostToSlack { expected_state_hash, .. } => expected_state_hash,
        }
    }

    pub fn type_tag(&self) -> &'static str {
        match self {
            Action::ReadInvoice { .. } => "read_invoice",
            Action::CreateDraft { .. } => "create_draft",
            Action::ApproveDraft { .. } => "approve_draft",
            Action::SubmitDraft { .. } => "submit_draft",
            Action::PostToSlack { .. } => "post_to_slack",
        }
    }
}


impl Action {
    pub fn to_value(&self) -> Value {
        match self {
            Action::ReadInvoice { invoice_id, nonce, expected_state_hash } => Value::object(vec![
                ("t", Value::text("read_invoice")),
                ("invoice_id", Value::text(invoice_id.clone())),
                ("nonce", Value::text(nonce.clone())),
                ("expected_state_hash", Value::text(expected_state_hash.clone())),
            ]),
            Action::CreateDraft { thread_id, invoice_id, customer_id, body, body_label, nonce, expected_state_hash } => Value::object(vec![
                ("t", Value::text("create_draft")),
                ("thread_id", Value::text(thread_id.clone())),
                ("invoice_id", Value::text(invoice_id.clone())),
                ("customer_id", Value::text(customer_id.clone())),
                ("body", Value::text(body.clone())),
                ("body_label", body_label.to_value()),
                ("nonce", Value::text(nonce.clone())),
                ("expected_state_hash", Value::text(expected_state_hash.clone())),
            ]),
            Action::ApproveDraft { draft_hash, approver_id, nonce, expected_state_hash } => Value::object(vec![
                ("t", Value::text("approve_draft")),
                ("draft_hash", Value::text(draft_hash.clone())),
                ("approver_id", Value::text(approver_id.clone())),
                ("nonce", Value::text(nonce.clone())),
                ("expected_state_hash", Value::text(expected_state_hash.clone())),
            ]),
            Action::SubmitDraft { draft_hash, recipient, recipient_label, nonce, expected_state_hash } => Value::object(vec![
                ("t", Value::text("submit_draft")),
                ("draft_hash", Value::text(draft_hash.clone())),
                ("recipient", Value::text(recipient.clone())),
                ("recipient_label", recipient_label.to_value()),
                ("nonce", Value::text(nonce.clone())),
                ("expected_state_hash", Value::text(expected_state_hash.clone())),
            ]),
            Action::PostToSlack { draft_hash, channel_id, channel_label, nonce, expected_state_hash } => Value::object(vec![
                ("t", Value::text("post_to_slack")),
                ("draft_hash", Value::text(draft_hash.clone())),
                ("channel_id", Value::text(channel_id.clone())),
                ("channel_label", channel_label.to_value()),
                ("nonce", Value::text(nonce.clone())),
                ("expected_state_hash", Value::text(expected_state_hash.clone())),
            ]),
        }
    }

    pub fn action_hash(&self) -> String {
        tagged_digest("confine.action.v1", &self.to_value())
    }
}

#[cfg(test)]
mod action_hash_tests {
    use super::*;
    use crate::labels::Label;

    #[test]
    fn diagnostic_confirmed_create_draft_action_hash() {
        let action = Action::CreateDraft {
            thread_id: "thread_001".into(), invoice_id: "inv_001".into(), customer_id: "cust_001".into(),
            body: "Invoice inv_001 remains overdue. Please review the outstanding balance.".into(),
            body_label: Label::customer("cust_001"),
            nonce: "nonce-exec-0001".into(),
            expected_state_hash: "sha256:20db1ed809ccec07704888c74ebae6d0ca9ee17119f6d46e03e2e0de88fa1576".into(),
        };
        assert_eq!(action.action_hash(), "sha256:0657dddb0069d3c5413069ccea45d98cafdddb872ec6dc3388442a90c21186bb");
    }
}
