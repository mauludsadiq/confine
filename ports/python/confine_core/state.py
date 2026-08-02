"""Committed state model and hash_state() (spec PROTOCOL.md sec 3, sec 9).

Direct port of packages/confine/state.fard, transliterated from the
already-vector-confirmed Rust port (ports/rust/src/state.rs) rather than
re-derived from FARD source independently -- lower risk since Rust
already proved every field-ordering/omission detail correct against real
fardrun output.
"""

from dataclasses import dataclass, field
from .canonical import encode
from .hash import tagged_digest


@dataclass
class Invoice:
    invoice_id: str
    customer_id: str
    status: str
    amount_cents: int
    label: object  # Label

    def to_dict(self):
        return {
            "invoice_id": self.invoice_id,
            "customer_id": self.customer_id,
            "status": self.status,
            "amount_cents": self.amount_cents,
            "label": {"kind": self.label.kind, "owner": self.label.owner, "compartments": list(self.label.compartments)},
        }


@dataclass
class Thread:
    thread_id: str
    customer_id: str

    def to_dict(self):
        return {"thread_id": self.thread_id, "customer_id": self.customer_id}


@dataclass
class Delivery:
    email_submitted: bool = False
    email_recipient: object = None
    slack_posted_channels: set = field(default_factory=set)

    def to_dict(self):
        return {
            "email": {"submitted": self.email_submitted, "recipient": self.email_recipient},
            "slack": {ch: True for ch in sorted(self.slack_posted_channels)},
        }


@dataclass
class Draft:
    draft_hash: str
    thread_id: str
    invoice_id: str
    customer_id: str
    body: str
    body_label: object  # Label
    created_by: str
    deliveries: Delivery

    def to_dict(self):
        return {
            "body": self.body,
            "body_label": {"kind": self.body_label.kind, "owner": self.body_label.owner, "compartments": list(self.body_label.compartments)},
            "created_by": self.created_by,
            "customer_id": self.customer_id,
            "deliveries": self.deliveries.to_dict(),
            "draft_hash": self.draft_hash,
            "invoice_id": self.invoice_id,
            "thread_id": self.thread_id,
        }


@dataclass
class Approval:
    draft_hash: str
    approver_id: str
    sequence: int

    def to_dict(self):
        return {"approver_id": self.approver_id, "draft_hash": self.draft_hash, "sequence": self.sequence}


@dataclass
class Counters:
    approved_total: int = 0
    drafted_total: int = 0
    slack_posted_total: int = 0
    submitted_total: int = 0

    def to_dict(self):
        return {
            "approved_total": self.approved_total,
            "drafted_total": self.drafted_total,
            "slack_posted_total": self.slack_posted_total,
            "submitted_total": self.submitted_total,
        }


@dataclass
class State:
    policy_version: str
    sequence: int
    invoices: dict
    threads: dict
    drafts: dict
    approvals: dict
    consumed_nonces: set
    counters: Counters
    submissions: list = field(default_factory=list)
    slack_posts: list = field(default_factory=list)
    previous_receipt_hash: str = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    def to_dict_for_hashing(self):
        """previous_receipt_hash is genuinely OMITTED, matching
        rec.remove(state, "previous_receipt_hash") -- not set to null."""
        return {
            "policy_version": self.policy_version,
            "sequence": self.sequence,
            "invoices": {k: v.to_dict() for k, v in self.invoices.items()},
            "threads": {k: v.to_dict() for k, v in self.threads.items()},
            "drafts": {k: v.to_dict() for k, v in self.drafts.items()},
            "approvals": {k: v.to_dict() for k, v in self.approvals.items()},
            "consumed_nonces": {n: True for n in self.consumed_nonces},
            "counters": self.counters.to_dict(),
            "submissions": self.submissions,
            "slack_posts": self.slack_posts,
        }


def hash_state(state: State) -> str:
    return tagged_digest("confine.state.v1", state.to_dict_for_hashing())


def get_invoice(state, invoice_id):
    return state.invoices.get(invoice_id)


def get_thread(state, thread_id):
    return state.threads.get(thread_id)


def get_draft(state, draft_hash):
    return state.drafts.get(draft_hash)


def get_approval(state, draft_hash):
    return state.approvals.get(draft_hash)


def nonce_consumed(state, nonce):
    return nonce in state.consumed_nonces
