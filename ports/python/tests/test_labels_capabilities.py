import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from confine_core import (
    public_label, internal_label, customer_label, secret_label, flows_to,
    Actor, Capabilities, operation_allowed,
)


def test_confirmed_flows_to_vectors():
    public = public_label()
    internal = internal_label()
    cust1 = customer_label("cust_001")
    cust2 = customer_label("cust_002")
    secret1 = secret_label("s1")
    secret2 = secret_label("s2")

    assert flows_to(public, internal) is True
    assert flows_to(public, cust1) is True
    assert flows_to(internal, public) is False
    assert flows_to(internal, internal) is True
    assert flows_to(internal, cust1) is True
    assert flows_to(cust1, cust1) is True
    assert flows_to(cust1, cust2) is False
    assert flows_to(cust1, internal) is False
    assert flows_to(cust1, secret1) is False
    assert flows_to(secret1, secret1) is True
    assert flows_to(secret1, secret2) is False
    assert flows_to(secret1, cust1) is False


def test_confirmed_operation_allowed_vectors():
    capabilities = Capabilities(actors={
        "drafter_1": Actor(role="drafter", operations=["read_invoice", "create_draft"]),
        "approver_1": Actor(role="approver", operations=["read_invoice", "approve_draft", "submit_draft"]),
    })
    assert operation_allowed(capabilities, "drafter_1", "read_invoice") is True
    assert operation_allowed(capabilities, "drafter_1", "create_draft") is True
    assert operation_allowed(capabilities, "drafter_1", "approve_draft") is False
    assert operation_allowed(capabilities, "approver_1", "submit_draft") is True
    assert operation_allowed(capabilities, "nobody", "read_invoice") is False
