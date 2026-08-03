// Certificate issuance and verification (spec PROTOCOL.md sec 10).
//
// Direct port of packages/confine/certificate.fard, transliterated from
// the vector-confirmed Rust and Python ports. Uses the v1-fard MAC
// construction (tag confine.certificate.mac.v1, key = raw UTF-8 bytes of
// the broker_secret string) matching current real fardrun behavior.

import { certificateMacV1Fard, taggedDigest } from "./hash.js";
import { hashState } from "./state.js";
import { capabilitiesDigest } from "./capabilities.js";
import { policyDigest } from "./policy.js";

function isLabel(v) {
  return v && typeof v === "object" && "kind" in v && "owner" in v;
}

function actionToValue(action) {
  const out = {};
  for (const [k, v] of Object.entries(action)) {
    out[k] = isLabel(v) ? { kind: v.kind, owner: v.owner, compartments: [...v.compartments] } : v;
  }
  return out;
}

export function actionHash(action) {
  return taggedDigest("confine.action.v1", actionToValue(action));
}

function obligationToValue(o) {
  const out = { ...o };
  if (isLabel(out.label)) {
    out.label = { kind: out.label.kind, owner: out.label.owner, compartments: [...out.label.compartments] };
  }
  return out;
}

function unsignedValue(cert) {
  return {
    t: "transition_certificate",
    version: 1,
    prior_state_hash: cert.priorStateHash,
    action_hash: cert.actionHash,
    actor_id: cert.actorId,
    policy_hash: cert.policyHash,
    capability_hash: cert.capabilityHash,
    nonce: cert.nonce,
    sequence: cert.sequence,
    obligations: cert.obligations.map(obligationToValue),
  };
}

export function issue(state, action, actorId, capabilities, policy, obligations, brokerSecret) {
  const unsigned = {
    priorStateHash: hashState(state),
    actionHash: actionHash(action),
    actorId,
    policyHash: policyDigest(policy),
    capabilityHash: capabilitiesDigest(capabilities),
    nonce: action.nonce,
    sequence: state.sequence,
    obligations,
  };
  const mac = certificateMacV1Fard(brokerSecret, unsignedValue(unsigned));
  return { ...unsigned, mac };
}

export function verify(certificate, state, action, actorId, capabilities, policy, brokerSecret) {
  if (!certificate.mac) return "CERTIFICATE_MISSING_MAC";
  const expectedMac = certificateMacV1Fard(brokerSecret, unsignedValue(certificate));
  if (certificate.mac !== expectedMac) return "CERTIFICATE_MAC_MISMATCH";
  if (certificate.priorStateHash !== hashState(state)) return "CERTIFICATE_STATE_MISMATCH";
  if (certificate.actionHash !== actionHash(action)) return "CERTIFICATE_ACTION_MISMATCH";
  if (certificate.actorId !== actorId) return "CERTIFICATE_ACTOR_MISMATCH";
  if (certificate.policyHash !== policyDigest(policy)) return "CERTIFICATE_POLICY_MISMATCH";
  if (certificate.capabilityHash !== capabilitiesDigest(capabilities)) return "CERTIFICATE_CAPABILITY_MISMATCH";
  if (certificate.nonce !== action.nonce) return "CERTIFICATE_NONCE_MISMATCH";
  if (certificate.sequence !== state.sequence) return "CERTIFICATE_SEQUENCE_MISMATCH";
  return null;
}

export { obligationToValue };
