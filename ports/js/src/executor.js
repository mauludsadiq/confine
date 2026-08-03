// Executor conformance (spec PROTOCOL.md sec 11) -- the normative
// invariant this entire project is built around.
//
// A conforming executor MUST independently invoke the complete policy
// decision procedure over the exact current state, canonical action,
// actor identity, capability set, and policy object, immediately before
// committing any effect. A certificate, its obligations, or a previously
// computed policy result MUST NOT substitute for this invocation.

import { verify as certificateVerify, obligationToValue } from "./certificate.js";
import { verify as policyVerify } from "./policy.js";
import { nonceConsumed } from "./state.js";
import { encode } from "./canonical.js";

export class ExecuteError extends Error {
  constructor(code, policyCode = null) {
    super(code);
    this.code = code;
    this.policyCode = policyCode;
  }
}

export function executeExact(state, action, actorId, capabilities, policy, certificate, brokerSecret) {
  const cv = certificateVerify(certificate, state, action, actorId, capabilities, policy, brokerSecret);
  if (cv !== null) {
    throw new ExecuteError(cv);
  }

  const decision = policyVerify(state, action, actorId, capabilities, policy);
  if (decision.t === "deny") {
    throw new ExecuteError("EXECUTOR_POLICY_DENIED", decision.code);
  }

  const certObligationsEncoded = encode(certificate.obligations.map(obligationToValue));
  const realObligationsEncoded = encode(decision.obligations.map(obligationToValue));
  if (certObligationsEncoded !== realObligationsEncoded) {
    throw new ExecuteError("CERTIFICATE_OBLIGATION_MISMATCH");
  }

  if (nonceConsumed(state, action.nonce)) {
    throw new ExecuteError("NONCE_REPLAY_AT_EXECUTOR");
  }

  return { t: "allow", obligations: decision.obligations };
}
