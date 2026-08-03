import test from "node:test";
import assert from "node:assert/strict";
import {
  makeState, makeCounters, hashState, customerLabel, internalLabel, verify,
  issue, certificateVerify, executeExact, ExecuteError,
} from "../src/index.js";

function buildPolicy() {
  return {
    version: "invoice-policy-v1", minNonceLength: 12, maxDraftChars: 2000,
    maxTotalDrafts: 100, maxTotalSubmissions: 20, approverRole: "approver",
    requireSeparationOfDuties: true,
    approvedRecipients: { cust_001: ["billing@example.test"], cust_002: ["accounts@example.test"] },
    approvedSlackChannels: { "channel-finance": internalLabel() },
    maxTotalSlackPosts: 10,
  };
}

function buildCapabilities() {
  return {
    actors: {
      drafter_1: { role: "drafter", operations: ["read_invoice", "create_draft"] },
      approver_1: { role: "approver", operations: ["read_invoice", "approve_draft", "submit_draft"] },
      poster_1: { role: "poster", operations: ["post_to_slack"] },
    },
    operationsRegistry: { read_invoice: true, create_draft: true, approve_draft: true, submit_draft: true, post_to_slack: true },
  };
}

function buildInitialState(policy) {
  return makeState({
    policyVersion: policy.version,
    sequence: 0,
    invoices: {
      inv_001: { invoiceId: "inv_001", customerId: "cust_001", status: "overdue", amountCents: 4200, label: customerLabel("cust_001") },
      inv_002: { invoiceId: "inv_002", customerId: "cust_002", status: "paid", amountCents: 9900, label: customerLabel("cust_002") },
    },
    threads: {
      thread_001: { threadId: "thread_001", customerId: "cust_001" },
      thread_002: { threadId: "thread_002", customerId: "cust_002" },
    },
    drafts: {}, approvals: {}, consumedNonces: new Set(), counters: makeCounters(),
  });
}

function confirmedAction(s0) {
  return {
    t: "create_draft", thread_id: "thread_001", invoice_id: "inv_001", customer_id: "cust_001",
    body: "Invoice inv_001 remains overdue. Please review the outstanding balance.",
    body_label: customerLabel("cust_001"),
    nonce: "nonce-exec-0001", expected_state_hash: hashState(s0),
  };
}

// Confirmed against examples/gen_executor_vectors2.fard, fardrun v1.7.0.

test("confirmed certificate MAC vector", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const action = confirmedAction(s0);
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  const secret = "0123456789abcdef0123456789abcdef";
  const cert = issue(s0, action, "drafter_1", capabilities, policy, decision.obligations, secret);
  assert.equal(cert.mac, "sha256:bda034f026465709c53c16f02db20824ee3476a95c0f5a76debc184c43619de7");
});

test("confirmed legit certificate verifies ok", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const action = confirmedAction(s0);
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  const secret = "0123456789abcdef0123456789abcdef";
  const cert = issue(s0, action, "drafter_1", capabilities, policy, decision.obligations, secret);
  assert.equal(certificateVerify(cert, s0, action, "drafter_1", capabilities, policy, secret), null);
});

test("confirmed tampered certificate rejected", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const action = confirmedAction(s0);
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  const secret = "0123456789abcdef0123456789abcdef";
  const cert = issue(s0, action, "drafter_1", capabilities, policy, decision.obligations, secret);
  const tampered = { ...cert, actorId: "attacker" };
  assert.equal(certificateVerify(tampered, s0, action, "attacker", capabilities, policy, secret), "CERTIFICATE_MAC_MISMATCH");
});

test("confirmed legit execution succeeds", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const action = confirmedAction(s0);
  const decision = verify(s0, action, "drafter_1", capabilities, policy);
  const secret = "0123456789abcdef0123456789abcdef";
  const cert = issue(s0, action, "drafter_1", capabilities, policy, decision.obligations, secret);
  const result = executeExact(s0, action, "drafter_1", capabilities, policy, cert, secret);
  assert.equal(result.t, "allow");
});

test("confirmed forged action rejected by independent policy rerun", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const badAction = {
    t: "create_draft", thread_id: "thread_001", invoice_id: "inv_001", customer_id: "cust_001",
    body: "test", body_label: customerLabel("cust_999"),
    nonce: "nonce-exec-0002", expected_state_hash: hashState(s0),
  };
  const badObligations = [
    { t: "bind_customer", customer_id: "cust_001" },
    { t: "body_label", label: customerLabel("cust_999") },
  ];
  const secret = "0123456789abcdef0123456789abcdef";
  const badCert = issue(s0, badAction, "drafter_1", capabilities, policy, badObligations, secret);
  try {
    executeExact(s0, badAction, "drafter_1", capabilities, policy, badCert, secret);
    assert.fail("expected ExecuteError");
  } catch (e) {
    assert.ok(e instanceof ExecuteError);
    assert.equal(e.code, "EXECUTOR_POLICY_DENIED");
    assert.equal(e.policyCode, "IFC_INVOICE_TO_BODY");
  }
});

test("confirmed obligation mismatch rejected", () => {
  const policy = buildPolicy();
  const capabilities = buildCapabilities();
  const s0 = buildInitialState(policy);
  const action = confirmedAction(s0);
  const mismatchedObligations = [
    { t: "bind_customer", customer_id: "cust_001" },
    { t: "body_label", label: customerLabel("cust_002") },
  ];
  const secret = "0123456789abcdef0123456789abcdef";
  const mismatchCert = issue(s0, action, "drafter_1", capabilities, policy, mismatchedObligations, secret);
  try {
    executeExact(s0, action, "drafter_1", capabilities, policy, mismatchCert, secret);
    assert.fail("expected ExecuteError");
  } catch (e) {
    assert.ok(e instanceof ExecuteError);
    assert.equal(e.code, "CERTIFICATE_OBLIGATION_MISMATCH");
  }
});
