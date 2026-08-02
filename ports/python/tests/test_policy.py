import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from confine_core import (
    State, Invoice, Thread, Draft, Approval, Delivery, Counters, hash_state,
    PolicyConfig, verify, Actor, Capabilities, customer_label,
)


def build_test_policy():
    return PolicyConfig(
        version="invoice-policy-v1", min_nonce_length=12, max_draft_chars=2000,
        max_total_drafts=100, max_total_submissions=20, approver_role="approver",
        require_separation_of_duties=True,
        approved_recipients={"cust_001": ["billing@example.test"]},
    )


def build_test_capabilities():
    return Capabilities(actors={
        "drafter_1": Actor(role="drafter", operations=["read_invoice", "create_draft"]),
        "approver_1": Actor(role="approver", operations=["read_invoice", "approve_draft", "submit_draft"]),
    })


def initial_state(policy):
    invoices = {"inv_001": Invoice(invoice_id="inv_001", customer_id="cust_001", status="overdue", amount_cents=4200, label=customer_label("cust_001"))}
    threads = {"thread_001": Thread(thread_id="thread_001", customer_id="cust_001")}
    return State(
        policy_version=policy.version, sequence=0, invoices=invoices, threads=threads,
        drafts={}, approvals={}, consumed_nonces=set(), counters=Counters(),
    )


# Every assertion below traces to a real decision captured via
# examples/gen_policy_vectors.fard against fardrun v1.7.0.

def test_confirmed_create_draft_allow():
    policy = build_test_policy()
    capabilities = build_test_capabilities()
    s0 = initial_state(policy)
    action = {
        "t": "create_draft", "thread_id": "thread_001", "invoice_id": "inv_001", "customer_id": "cust_001",
        "body": "Invoice inv_001 remains overdue. Please review the outstanding balance.",
        "body_label": customer_label("cust_001"),
        "nonce": "nonce-vec-0001", "expected_state_hash": hash_state(s0),
    }
    decision = verify(s0, action, "drafter_1", capabilities, policy)
    assert decision["t"] == "allow"
    assert decision["obligations"][0]["t"] == "bind_customer"
    assert decision["obligations"][1]["t"] == "body_label"


def test_confirmed_deny_capability():
    policy = build_test_policy()
    capabilities = build_test_capabilities()
    s0 = initial_state(policy)
    action = {
        "t": "approve_draft",
        "draft_hash": "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba",
        "approver_id": "drafter_1", "nonce": "nonce-vec-0004", "expected_state_hash": hash_state(s0),
    }
    decision = verify(s0, action, "drafter_1", capabilities, policy)
    assert decision["t"] == "deny"
    assert decision["code"] == "CAPABILITY_DENIED"


def test_confirmed_deny_ifc_invoice_to_body():
    policy = build_test_policy()
    capabilities = build_test_capabilities()
    s0 = initial_state(policy)
    action = {
        "t": "create_draft", "thread_id": "thread_001", "invoice_id": "inv_001", "customer_id": "cust_001",
        "body": "test", "body_label": customer_label("cust_999"),
        "nonce": "nonce-vec-0005", "expected_state_hash": hash_state(s0),
    }
    decision = verify(s0, action, "drafter_1", capabilities, policy)
    assert decision["t"] == "deny"
    assert decision["code"] == "IFC_INVOICE_TO_BODY"


def test_confirmed_deny_stale_state():
    policy = build_test_policy()
    capabilities = build_test_capabilities()
    s0 = initial_state(policy)
    action = {
        "t": "read_invoice", "invoice_id": "inv_001", "nonce": "nonce-vec-0006",
        "expected_state_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }
    decision = verify(s0, action, "drafter_1", capabilities, policy)
    assert decision["t"] == "deny"
    assert decision["code"] == "STALE_STATE"


def test_confirmed_approve_and_submit_allow_full_sequence():
    policy = build_test_policy()
    capabilities = build_test_capabilities()
    s0 = initial_state(policy)
    draft_hash = "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba"

    s1 = s0
    s1.drafts = dict(s0.drafts)
    s1.drafts[draft_hash] = Draft(
        draft_hash=draft_hash, thread_id="thread_001", invoice_id="inv_001", customer_id="cust_001",
        body="x", body_label=customer_label("cust_001"), created_by="drafter_1", deliveries=Delivery(),
    )

    approve_action = {
        "t": "approve_draft", "draft_hash": draft_hash, "approver_id": "approver_1",
        "nonce": "nonce-vec-0002", "expected_state_hash": hash_state(s1),
    }
    approve_decision = verify(s1, approve_action, "approver_1", capabilities, policy)
    assert approve_decision["t"] == "allow"
    assert approve_decision["obligations"][0]["t"] == "approve_exact_hash"

    s1.approvals = dict(s1.approvals)
    s1.approvals[draft_hash] = Approval(draft_hash=draft_hash, approver_id="approver_1", sequence=1)

    submit_action = {
        "t": "submit_draft", "draft_hash": draft_hash, "recipient": "billing@example.test",
        "recipient_label": customer_label("cust_001"),
        "nonce": "nonce-vec-0003", "expected_state_hash": hash_state(s1),
    }
    submit_decision = verify(s1, submit_action, "approver_1", capabilities, policy)
    assert submit_decision["t"] == "allow"
    assert submit_decision["obligations"][0]["t"] == "submit_exact_hash"
    assert submit_decision["obligations"][1]["t"] == "recipient"
