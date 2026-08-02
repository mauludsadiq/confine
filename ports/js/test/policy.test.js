import test from "node:test";
import assert from "node:assert/strict";
import {
  makeState, makeDelivery, makeCounters, hashState, customerLabel, verify,
} from "../src/index.js";

function testPolicy() {
  return {
    version: "invoice-policy-v1", minNonceLength: 12, maxDraftChars: 2000,
    maxTotalDrafts: 100, maxTotalSubmissions: 20, approverRole: "approver",
    requireSeparationOfDuties: true,
    approvedRecipients: { cust_001: ["billing@example.test"] },
  };
}

function testCapabilities() {
  return {
    actors: {
      drafter_1: { role: "drafter", operations: ["read_invoice", "create_draft"] },
      approver_1: { role: "approver", operations: ["read_invoice", "approve_draft", "submit_draft"] },
    },
  };
}

function initialState(policy) {
  return makeState({
    policyVersion: policy.version,
    sequence: 0,
    invoices: { inv_001: { invoiceId: "inv_001", customerId: "cust_001", status: "overdue", amountCents: 4200, label: customerLabel("cust_001") } },
    threads: { thread_001: { threadId: "thread_001", customerId: "cust_001" } },
    drafts: {},
    approvals: {},
    consumedNonces: new Set(),
    counters: makeCounters(),
  });
}

// Every assertion below traces to a real decision captured via
// examples/gen_policy_vectors.fard against fardrun v1.7.0.

test("confirmed create_draft allow", () => {
  const policy = testPolicy();
  const capabilities = testCapabilities();
  const s0 = initialState(policy);
  const action = {
    t: "create_draft", thread_id: "thread_001", invoice_id: "inv_001", customer_id: "cust_001",
    body: "Invoice inv_001 remains overdue. Please review the outstanding balance.",
    body_label: customerLabel("cust_001"),
    nonce: "nonce-vec-0001", expected_state_hash: hashState(s0),
  };
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  assert.equal(decision.t, "allow");
  assert.equal(decision.obligations[0].t, "bind_customer");
  assert.equal(decision.obligations[1].t, "body_label");
});

test("confirmed deny CAPABILITY_DENIED", () => {
  const policy = testPolicy();
  const capabilities = testCapabilities();
  const s0 = initialState(policy);
  const action = {
    t: "approve_draft",
    draft_hash: "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba",
    approver_id: "drafter_1", nonce: "nonce-vec-0004", expected_state_hash: hashState(s0),
  };
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  assert.equal(decision.t, "deny");
  assert.equal(decision.code, "CAPABILITY_DENIED");
});

test("confirmed deny IFC_INVOICE_TO_BODY", () => {
  const policy = testPolicy();
  const capabilities = testCapabilities();
  const s0 = initialState(policy);
  const action = {
    t: "create_draft", thread_id: "thread_001", invoice_id: "inv_001", customer_id: "cust_001",
    body: "test", body_label: customerLabel("cust_999"),
    nonce: "nonce-vec-0005", expected_state_hash: hashState(s0),
  };
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  assert.equal(decision.t, "deny");
  assert.equal(decision.code, "IFC_INVOICE_TO_BODY");
});

test("confirmed deny STALE_STATE", () => {
  const policy = testPolicy();
  const capabilities = testCapabilities();
  const s0 = initialState(policy);
  const action = {
    t: "read_invoice", invoice_id: "inv_001", nonce: "nonce-vec-0006",
    expected_state_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  };
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  assert.equal(decision.t, "deny");
  assert.equal(decision.code, "STALE_STATE");
});

test("confirmed approve and submit allow full sequence", () => {
  const policy = testPolicy();
  const capabilities = testCapabilities();
  const s1 = initialState(policy);
  const draftHash = "sha256:814ad6f5cfcff19fb424c26ccf6eeb09c4f4c9eda27dd5903e8b3f24ccdf0aba";

  s1.drafts[draftHash] = {
    draftHash, threadId: "thread_001", invoiceId: "inv_001", customerId: "cust_001",
    body: "x", bodyLabel: customerLabel("cust_001"), createdBy: "drafter_1", deliveries: makeDelivery(),
  };

  const approveAction = {
    t: "approve_draft", draft_hash: draftHash, approver_id: "approver_1",
    nonce: "nonce-vec-0002", expected_state_hash: hashState(s1),
  };
  const approveDecision = verify(s1, approveAction, "approver_1", capabilities, policy);
  assert.equal(approveDecision.t, "allow");
  assert.equal(approveDecision.obligations[0].t, "approve_exact_hash");

  s1.approvals[draftHash] = { draftHash, approverId: "approver_1", sequence: 1 };

  const submitAction = {
    t: "submit_draft", draft_hash: draftHash, recipient: "billing@example.test",
    recipient_label: customerLabel("cust_001"),
    nonce: "nonce-vec-0003", expected_state_hash: hashState(s1),
  };
  const submitDecision = verify(s1, submitAction, "approver_1", capabilities, policy);
  assert.equal(submitDecision.t, "allow");
  assert.equal(submitDecision.obligations[0].t, "submit_exact_hash");
  assert.equal(submitDecision.obligations[1].t, "recipient");
});
