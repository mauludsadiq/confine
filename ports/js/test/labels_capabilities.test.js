import test from "node:test";
import assert from "node:assert/strict";
import {
  publicLabel, internalLabel, customerLabel, secretLabel, flowsTo,
  operationAllowed,
} from "../src/index.js";

test("confirmed flows_to vectors", () => {
  const pub = publicLabel();
  const internal = internalLabel();
  const cust1 = customerLabel("cust_001");
  const cust2 = customerLabel("cust_002");
  const secret1 = secretLabel("s1");
  const secret2 = secretLabel("s2");

  assert.equal(flowsTo(pub, internal), true);
  assert.equal(flowsTo(pub, cust1), true);
  assert.equal(flowsTo(internal, pub), false);
  assert.equal(flowsTo(internal, internal), true);
  assert.equal(flowsTo(internal, cust1), true);
  assert.equal(flowsTo(cust1, cust1), true);
  assert.equal(flowsTo(cust1, cust2), false);
  assert.equal(flowsTo(cust1, internal), false);
  assert.equal(flowsTo(cust1, secret1), false);
  assert.equal(flowsTo(secret1, secret1), true);
  assert.equal(flowsTo(secret1, secret2), false);
  assert.equal(flowsTo(secret1, cust1), false);
});

test("confirmed operation_allowed vectors", () => {
  const capabilities = {
    actors: {
      drafter_1: { role: "drafter", operations: ["read_invoice", "create_draft"] },
      approver_1: { role: "approver", operations: ["read_invoice", "approve_draft", "submit_draft"] },
    },
  };
  assert.equal(operationAllowed(capabilities, "drafter_1", "read_invoice"), true);
  assert.equal(operationAllowed(capabilities, "drafter_1", "create_draft"), true);
  assert.equal(operationAllowed(capabilities, "drafter_1", "approve_draft"), false);
  assert.equal(operationAllowed(capabilities, "approver_1", "submit_draft"), true);
  assert.equal(operationAllowed(capabilities, "nobody", "read_invoice"), false);
});
