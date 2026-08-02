//! Closed action algebra (spec PROTOCOL.md sec 6).

use crate::labels::Label;

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
