import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from confine_core import State, Invoice, Thread, Counters, hash_state, PolicyConfig, verify as policy_verify, Actor, Capabilities, customer_label, internal_label
from confine_core.certificate import issue, verify as certificate_verify
from confine_core.executor import execute_exact, ExecuteError


def build_policy():
    return PolicyConfig(
        version="invoice-policy-v1", min_nonce_length=12, max_draft_chars=2000,
        max_total_drafts=100, max_total_submissions=20, approver_role="approver",
        require_separation_of_duties=True,
        approved_recipients={"cust_001": ["billing@example.test"], "cust_002": ["accounts@example.test"]},
        approved_slack_channels={"channel-finance": internal_label()},
        max_total_slack_posts=10,
    )


def build_capabilities():
    return Capabilities(actors={
        "drafter_1": Actor(role="drafter", operations=["read_invoice", "create_draft"]),
        "approver_1": Actor(role="approver", operations=["read_invoice", "approve_draft", "submit_draft"]),
        "poster_1": Actor(role="poster", operations=["post_to_slack"]),
    }, operations_registry={op: True for op in ["read_invoice", "create_draft", "approve_draft", "submit_draft", "post_to_slack"]})


def build_initial_state(policy):
    invoices = {
        "inv_001": Invoice(invoice_id="inv_001", customer_id="cust_001", status="overdue", amount_cents=4200, label=customer_label("cust_001")),
        "inv_002": Invoice(invoice_id="inv_002", customer_id="cust_002", status="paid", amount_cents=9900, label=customer_label("cust_002")),
    }
    threads = {
        "thread_001": Thread(thread_id="thread_001", customer_id="cust_001"),
        "thread_002": Thread(thread_id="thread_002", customer_id="cust_002"),
    }
    return State(policy_version=policy.version, sequence=0, invoices=invoices, threads=threads, drafts={}, approvals={}, consumed_nonces=set(), counters=Counters())


def confirmed_action(s0):
    return {
        "t": "create_draft", "thread_id": "thread_001", "invoice_id": "inv_001", "customer_id": "cust_001",
        "body": "Invoice inv_001 remains overdue. Please review the outstanding balance.",
        "body_label": customer_label("cust_001"),
        "nonce": "nonce-exec-0001", "expected_state_hash": hash_state(s0),
    }


# Confirmed against examples/gen_executor_vectors2.fard, fardrun v1.7.0.

def test_confirmed_vector_certificate_mac():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    action = confirmed_action(s0)
    decision = policy_verify(s0, action, "drafter_1", capabilities, policy)
    secret = "0123456789abcdef0123456789abcdef"
    cert = issue(s0, action, "drafter_1", capabilities, policy, decision["obligations"], secret)
    assert cert.mac == "sha256:bda034f026465709c53c16f02db20824ee3476a95c0f5a76debc184c43619de7"


def test_confirmed_legit_certificate_verifies_ok():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    action = confirmed_action(s0)
    decision = policy_verify(s0, action, "drafter_1", capabilities, policy)
    secret = "0123456789abcdef0123456789abcdef"
    cert = issue(s0, action, "drafter_1", capabilities, policy, decision["obligations"], secret)
    assert certificate_verify(cert, s0, action, "drafter_1", capabilities, policy, secret) is None


def test_confirmed_tampered_certificate_rejected():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    action = confirmed_action(s0)
    decision = policy_verify(s0, action, "drafter_1", capabilities, policy)
    secret = "0123456789abcdef0123456789abcdef"
    cert = issue(s0, action, "drafter_1", capabilities, policy, decision["obligations"], secret)
    cert.actor_id = "attacker"
    result = certificate_verify(cert, s0, action, "attacker", capabilities, policy, secret)
    assert result.code == "CERTIFICATE_MAC_MISMATCH"


def test_confirmed_legit_execution_succeeds():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    action = confirmed_action(s0)
    decision = policy_verify(s0, action, "drafter_1", capabilities, policy)
    secret = "0123456789abcdef0123456789abcdef"
    cert = issue(s0, action, "drafter_1", capabilities, policy, decision["obligations"], secret)
    result = execute_exact(s0, action, "drafter_1", capabilities, policy, cert, secret)
    assert result["t"] == "allow"


def test_confirmed_forged_action_rejected_by_independent_policy_rerun():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    bad_action = {
        "t": "create_draft", "thread_id": "thread_001", "invoice_id": "inv_001", "customer_id": "cust_001",
        "body": "test", "body_label": customer_label("cust_999"),
        "nonce": "nonce-exec-0002", "expected_state_hash": hash_state(s0),
    }
    bad_obligations = [
        {"t": "bind_customer", "customer_id": "cust_001"},
        {"t": "body_label", "label": customer_label("cust_999")},
    ]
    secret = "0123456789abcdef0123456789abcdef"
    bad_cert = issue(s0, bad_action, "drafter_1", capabilities, policy, bad_obligations, secret)
    try:
        execute_exact(s0, bad_action, "drafter_1", capabilities, policy, bad_cert, secret)
        assert False, "expected ExecuteError"
    except ExecuteError as e:
        assert e.code == "EXECUTOR_POLICY_DENIED"
        assert e.policy_code == "IFC_INVOICE_TO_BODY"


def test_confirmed_obligation_mismatch_rejected():
    policy = build_policy()
    capabilities = build_capabilities()
    s0 = build_initial_state(policy)
    action = confirmed_action(s0)
    mismatched_obligations = [
        {"t": "bind_customer", "customer_id": "cust_001"},
        {"t": "body_label", "label": customer_label("cust_002")},
    ]
    secret = "0123456789abcdef0123456789abcdef"
    mismatch_cert = issue(s0, action, "drafter_1", capabilities, policy, mismatched_obligations, secret)
    try:
        execute_exact(s0, action, "drafter_1", capabilities, policy, mismatch_cert, secret)
        assert False, "expected ExecuteError"
    except ExecuteError as e:
        assert e.code == "CERTIFICATE_OBLIGATION_MISMATCH"
