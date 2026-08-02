// Committed state model and hashState() (spec PROTOCOL.md sec 3, sec 9).
//
// Direct port of packages/confine/state.fard, transliterated from the
// already-vector-confirmed Rust and Python ports.

import { taggedDigest } from "./hash.js";

export function makeCounters() {
  return { approvedTotal: 0, draftedTotal: 0, slackPostedTotal: 0, submittedTotal: 0 };
}

function countersToValue(c) {
  return {
    approved_total: c.approvedTotal,
    drafted_total: c.draftedTotal,
    slack_posted_total: c.slackPostedTotal,
    submitted_total: c.submittedTotal,
  };
}

function invoiceToValue(inv) {
  return {
    invoice_id: inv.invoiceId,
    customer_id: inv.customerId,
    status: inv.status,
    amount_cents: inv.amountCents,
    label: inv.label,
  };
}

function threadToValue(th) {
  return { thread_id: th.threadId, customer_id: th.customerId };
}

export function makeDelivery() {
  return { emailSubmitted: false, emailRecipient: null, slackPostedChannels: new Set() };
}

function deliveryToValue(d) {
  const slack = {};
  for (const ch of [...d.slackPostedChannels].sort()) slack[ch] = true;
  return {
    email: { submitted: d.emailSubmitted, recipient: d.emailRecipient },
    slack,
  };
}

function draftToValue(d) {
  return {
    body: d.body,
    body_label: d.bodyLabel,
    created_by: d.createdBy,
    customer_id: d.customerId,
    deliveries: deliveryToValue(d.deliveries),
    draft_hash: d.draftHash,
    invoice_id: d.invoiceId,
    thread_id: d.threadId,
  };
}

function approvalToValue(a) {
  return { approver_id: a.approverId, draft_hash: a.draftHash, sequence: a.sequence };
}

export function makeState({ policyVersion, sequence, invoices, threads, drafts, approvals, consumedNonces, counters, submissions = [], slackPosts = [] }) {
  return {
    policyVersion, sequence, invoices, threads, drafts, approvals, consumedNonces, counters,
    submissions, slackPosts,
    previousReceiptHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  };
}

// previous_receipt_hash is genuinely OMITTED, matching rec.remove() --
// not set to null.
function stateToValueForHashing(state) {
  const invoices = {};
  for (const [k, v] of Object.entries(state.invoices)) invoices[k] = invoiceToValue(v);
  const threads = {};
  for (const [k, v] of Object.entries(state.threads)) threads[k] = threadToValue(v);
  const drafts = {};
  for (const [k, v] of Object.entries(state.drafts)) drafts[k] = draftToValue(v);
  const approvals = {};
  for (const [k, v] of Object.entries(state.approvals)) approvals[k] = approvalToValue(v);
  const consumedNonces = {};
  for (const n of state.consumedNonces) consumedNonces[n] = true;

  return {
    policy_version: state.policyVersion,
    sequence: state.sequence,
    invoices,
    threads,
    drafts,
    approvals,
    consumed_nonces: consumedNonces,
    counters: countersToValue(state.counters),
    submissions: state.submissions,
    slack_posts: state.slackPosts,
  };
}

export function hashState(state) {
  return taggedDigest("confine.state.v1", stateToValueForHashing(state));
}

export function getInvoice(state, invoiceId) {
  return state.invoices[invoiceId] ?? null;
}

export function getThread(state, threadId) {
  return state.threads[threadId] ?? null;
}

export function getDraft(state, draftHash) {
  return state.drafts[draftHash] ?? null;
}

export function getApproval(state, draftHash) {
  return state.approvals[draftHash] ?? null;
}

export function nonceConsumed(state, nonce) {
  return state.consumedNonces.has(nonce);
}
