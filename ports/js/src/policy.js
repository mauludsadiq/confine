// Deterministic policy decision procedure (spec PROTOCOL.md sec 9).
//
// Direct port of packages/confine/policy.fard, transliterated from the
// vector-confirmed Rust and Python ports.

import { flowsTo } from "./labels.js";
import { operationAllowed, actorRole } from "./capabilities.js";
import { getInvoice, getThread, getDraft, getApproval, nonceConsumed, hashState } from "./state.js";

function deny(code) {
  return { t: "deny", code };
}

function allow(obligations) {
  return { t: "allow", obligations };
}

export function obligationsForCreateDraft(customerId, bodyLabel) {
  return [
    { t: "bind_customer", customer_id: customerId },
    { t: "body_label", label: bodyLabel },
  ];
}

export function obligationsForApproveDraft(draftHash) {
  return [{ t: "approve_exact_hash", draft_hash: draftHash }];
}

export function obligationsForSubmitDraft(draftHash, recipient) {
  return [
    { t: "submit_exact_hash", draft_hash: draftHash },
    { t: "recipient", recipient },
  ];
}

function commonChecks(state, action, actorId, capabilities, policy) {
  if (state.policyVersion !== policy.version) return deny("POLICY_VERSION_MISMATCH");
  if (action.expected_state_hash !== hashState(state)) return deny("STALE_STATE");
  if (nonceConsumed(state, action.nonce)) return deny("NONCE_REPLAY");
  if (action.nonce.length < policy.minNonceLength) return deny("NONCE_TOO_SHORT");
  if (!operationAllowed(capabilities, actorId, action.t)) return deny("CAPABILITY_DENIED");
  return null;
}

export function verify(state, action, actorId, capabilities, policy) {
  const common = commonChecks(state, action, actorId, capabilities, policy);
  if (common !== null) return common;

  switch (action.t) {
    case "read_invoice": {
      const invoice = getInvoice(state, action.invoice_id);
      if (!invoice) return deny("INVOICE_NOT_FOUND");
      return allow([{ t: "result_label", label: invoice.label }]);
    }

    case "create_draft": {
      const invoice = getInvoice(state, action.invoice_id);
      if (!invoice) return deny("INVOICE_NOT_FOUND");
      const thread = getThread(state, action.thread_id);
      if (!thread) return deny("THREAD_NOT_FOUND");
      if (invoice.customerId !== action.customer_id) return deny("INVOICE_CUSTOMER_MISMATCH");
      if (thread.customerId !== action.customer_id) return deny("THREAD_CUSTOMER_MISMATCH");
      if (!flowsTo(invoice.label, action.body_label)) return deny("IFC_INVOICE_TO_BODY");
      if (action.body_label.kind !== "customer" || action.body_label.owner !== action.customer_id) return deny("BODY_LABEL_OWNER_MISMATCH");
      if (action.body.length === 0) return deny("EMPTY_DRAFT");
      if (action.body.length > policy.maxDraftChars) return deny("DRAFT_TOO_LARGE");
      if (state.counters.draftedTotal >= policy.maxTotalDrafts) return deny("DRAFT_QUOTA");
      return allow(obligationsForCreateDraft(action.customer_id, action.body_label));
    }

    case "approve_draft": {
      const draft = getDraft(state, action.draft_hash);
      if (!draft) return deny("DRAFT_NOT_FOUND");
      const role = actorRole(capabilities, actorId);
      if (role !== policy.approverRole) return deny("APPROVER_ROLE_REQUIRED");
      if (actorId !== action.approver_id) return deny("APPROVER_ID_MISMATCH");
      if (draft.createdBy === actorId && policy.requireSeparationOfDuties) return deny("SEPARATION_OF_DUTIES");
      if (getApproval(state, action.draft_hash) !== null) return deny("ALREADY_APPROVED");
      return allow(obligationsForApproveDraft(action.draft_hash));
    }

    case "submit_draft": {
      const draft = getDraft(state, action.draft_hash);
      if (!draft) return deny("DRAFT_NOT_FOUND");
      if (getApproval(state, action.draft_hash) === null) return deny("APPROVAL_REQUIRED");
      if (draft.deliveries.emailSubmitted) return deny("ALREADY_SUBMITTED");
      const recipients = policy.approvedRecipients[draft.customerId] ?? [];
      if (!recipients.includes(action.recipient)) return deny("RECIPIENT_NOT_APPROVED");
      if (action.recipient_label.kind !== "customer" || action.recipient_label.owner !== draft.customerId) return deny("RECIPIENT_LABEL_OWNER_MISMATCH");
      if (!flowsTo(draft.bodyLabel, action.recipient_label)) return deny("IFC_BODY_TO_RECIPIENT");
      if (state.counters.submittedTotal >= policy.maxTotalSubmissions) return deny("SUBMISSION_QUOTA");
      return allow(obligationsForSubmitDraft(action.draft_hash, action.recipient));
    }

    case "post_to_slack": {
      const draft = getDraft(state, action.draft_hash);
      if (!draft) return deny("DRAFT_NOT_FOUND");
      if (getApproval(state, action.draft_hash) === null) return deny("APPROVAL_REQUIRED");
      const channel = policy.approvedSlackChannels?.[action.channel_id];
      if (!channel) return deny("CHANNEL_NOT_FOUND");
      if (JSON.stringify(action.channel_label) !== JSON.stringify(channel)) return deny("CHANNEL_LABEL_MISMATCH");
      if (!flowsTo(draft.bodyLabel, channel)) return deny("IFC_BODY_TO_CHANNEL");
      if (draft.deliveries.slackPostedChannels.has(action.channel_id)) return deny("ALREADY_POSTED");
      if (state.counters.slackPostedTotal >= (policy.maxTotalSlackPosts ?? 10)) return deny("SLACK_QUOTA");
      return allow([
        { t: "post_exact_hash", draft_hash: action.draft_hash },
        { t: "channel", channel_id: action.channel_id },
      ]);
    }

    default:
      return deny("UNKNOWN_ACTION");
  }
}
