"""Deterministic policy decision procedure (spec PROTOCOL.md sec 9).

Direct port of packages/confine/policy.fard, transliterated from the
vector-confirmed Rust port. Every branch traces to a specific line in
policy.fard and to a real captured decision -- see tests.
"""

from dataclasses import dataclass, field
from .labels import flows_to
from .capabilities import operation_allowed, actor_role
from .state import get_invoice, get_thread, get_draft, get_approval, nonce_consumed, hash_state


@dataclass
class PolicyConfig:
    version: str
    min_nonce_length: int
    max_draft_chars: int
    max_total_drafts: int
    max_total_submissions: int
    approver_role: str
    require_separation_of_duties: bool
    approved_recipients: dict
    approved_slack_channels: dict = field(default_factory=dict)
    max_total_slack_posts: int = 10


def deny(code):
    return {"t": "deny", "code": code}


def allow(obligations):
    return {"t": "allow", "obligations": obligations}


def obligations_for_create_draft(customer_id, body_label):
    return [
        {"t": "bind_customer", "customer_id": customer_id},
        {"t": "body_label", "label": body_label},
    ]


def obligations_for_approve_draft(draft_hash):
    return [{"t": "approve_exact_hash", "draft_hash": draft_hash}]


def obligations_for_submit_draft(draft_hash, recipient):
    return [
        {"t": "submit_exact_hash", "draft_hash": draft_hash},
        {"t": "recipient", "recipient": recipient},
    ]


def _common_checks(state, action, actor_id, capabilities, policy):
    if state.policy_version != policy.version:
        return deny("POLICY_VERSION_MISMATCH")
    if action["expected_state_hash"] != hash_state(state):
        return deny("STALE_STATE")
    if nonce_consumed(state, action["nonce"]):
        return deny("NONCE_REPLAY")
    if len(action["nonce"]) < policy.min_nonce_length:
        return deny("NONCE_TOO_SHORT")
    if not operation_allowed(capabilities, actor_id, action["t"]):
        return deny("CAPABILITY_DENIED")
    return None


def verify(state, action, actor_id, capabilities, policy):
    common = _common_checks(state, action, actor_id, capabilities, policy)
    if common is not None:
        return common

    t = action["t"]

    if t == "read_invoice":
        invoice = get_invoice(state, action["invoice_id"])
        if invoice is None:
            return deny("INVOICE_NOT_FOUND")
        return allow([{"t": "result_label", "label": invoice.label}])

    if t == "create_draft":
        invoice = get_invoice(state, action["invoice_id"])
        if invoice is None:
            return deny("INVOICE_NOT_FOUND")
        thread = get_thread(state, action["thread_id"])
        if thread is None:
            return deny("THREAD_NOT_FOUND")
        if invoice.customer_id != action["customer_id"]:
            return deny("INVOICE_CUSTOMER_MISMATCH")
        if thread.customer_id != action["customer_id"]:
            return deny("THREAD_CUSTOMER_MISMATCH")
        if not flows_to(invoice.label, action["body_label"]):
            return deny("IFC_INVOICE_TO_BODY")
        if action["body_label"].kind != "customer" or action["body_label"].owner != action["customer_id"]:
            return deny("BODY_LABEL_OWNER_MISMATCH")
        if len(action["body"]) == 0:
            return deny("EMPTY_DRAFT")
        if len(action["body"]) > policy.max_draft_chars:
            return deny("DRAFT_TOO_LARGE")
        if state.counters.drafted_total >= policy.max_total_drafts:
            return deny("DRAFT_QUOTA")
        return allow(obligations_for_create_draft(action["customer_id"], action["body_label"]))

    if t == "approve_draft":
        draft = get_draft(state, action["draft_hash"])
        if draft is None:
            return deny("DRAFT_NOT_FOUND")
        role = actor_role(capabilities, actor_id)
        if role != policy.approver_role:
            return deny("APPROVER_ROLE_REQUIRED")
        if actor_id != action["approver_id"]:
            return deny("APPROVER_ID_MISMATCH")
        if draft.created_by == actor_id and policy.require_separation_of_duties:
            return deny("SEPARATION_OF_DUTIES")
        if get_approval(state, action["draft_hash"]) is not None:
            return deny("ALREADY_APPROVED")
        return allow(obligations_for_approve_draft(action["draft_hash"]))

    if t == "submit_draft":
        draft = get_draft(state, action["draft_hash"])
        if draft is None:
            return deny("DRAFT_NOT_FOUND")
        if get_approval(state, action["draft_hash"]) is None:
            return deny("APPROVAL_REQUIRED")
        if draft.deliveries.email_submitted:
            return deny("ALREADY_SUBMITTED")
        recipients = policy.approved_recipients.get(draft.customer_id, [])
        if action["recipient"] not in recipients:
            return deny("RECIPIENT_NOT_APPROVED")
        if action["recipient_label"].kind != "customer" or action["recipient_label"].owner != draft.customer_id:
            return deny("RECIPIENT_LABEL_OWNER_MISMATCH")
        if not flows_to(draft.body_label, action["recipient_label"]):
            return deny("IFC_BODY_TO_RECIPIENT")
        if state.counters.submitted_total >= policy.max_total_submissions:
            return deny("SUBMISSION_QUOTA")
        return allow(obligations_for_submit_draft(action["draft_hash"], action["recipient"]))

    if t == "post_to_slack":
        draft = get_draft(state, action["draft_hash"])
        if draft is None:
            return deny("DRAFT_NOT_FOUND")
        if get_approval(state, action["draft_hash"]) is None:
            return deny("APPROVAL_REQUIRED")
        channel = policy.approved_slack_channels.get(action["channel_id"])
        if channel is None:
            return deny("CHANNEL_NOT_FOUND")
        if action["channel_label"] != channel:
            return deny("CHANNEL_LABEL_MISMATCH")
        if not flows_to(draft.body_label, channel):
            return deny("IFC_BODY_TO_CHANNEL")
        if action["channel_id"] in draft.deliveries.slack_posted_channels:
            return deny("ALREADY_POSTED")
        if state.counters.slack_posted_total >= policy.max_total_slack_posts:
            return deny("SLACK_QUOTA")
        return allow([
            {"t": "post_exact_hash", "draft_hash": action["draft_hash"]},
            {"t": "channel", "channel_id": action["channel_id"]},
        ])

    return deny("UNKNOWN_ACTION")


def _policy_to_dict(policy: PolicyConfig) -> dict:
    return {
        "approved_recipients": {k: list(v) for k, v in policy.approved_recipients.items()},
        "approved_slack_channels": {
            k: {"label": {"kind": v.kind, "owner": v.owner, "compartments": list(v.compartments)}}
            for k, v in policy.approved_slack_channels.items()
        },
        "approver_role": policy.approver_role,
        "max_draft_chars": policy.max_draft_chars,
        "max_total_drafts": policy.max_total_drafts,
        "max_total_slack_posts": policy.max_total_slack_posts,
        "max_total_submissions": policy.max_total_submissions,
        "min_nonce_length": policy.min_nonce_length,
        "require_separation_of_duties": policy.require_separation_of_duties,
        "version": policy.version,
    }


def digest(policy: PolicyConfig) -> str:
    from .hash import tagged_digest
    return tagged_digest("confine.policy.v1", _policy_to_dict(policy))
