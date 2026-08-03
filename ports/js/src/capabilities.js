// Capability model (spec PROTOCOL.md sec 8).
//
// Direct port of packages/confine/capabilities.fard's operation_allowed().
// No default-allow: an actor absent from the map, or an operation absent
// from that actor's explicit list, returns false.

import { taggedDigest } from "./hash.js";

export function operationAllowed(capabilities, actorId, operation) {
  const actor = capabilities.actors[actorId];
  if (!actor) return false;
  return actor.operations.includes(operation);
}

export function actorRole(capabilities, actorId) {
  const actor = capabilities.actors[actorId];
  return actor ? actor.role : null;
}


export function capabilitiesToValue(capabilities) {
  const actors = {};
  for (const [k, v] of Object.entries(capabilities.actors)) {
    actors[k] = { role: v.role, operations: [...v.operations] };
  }
  const operations = {};
  for (const [k, v] of Object.entries(capabilities.operationsRegistry ?? {})) {
    operations[k] = v;
  }
  return { actors, operations };
}

export function capabilitiesDigest(capabilities) {
  return taggedDigest("confine.capabilities.v1", capabilitiesToValue(capabilities));
}
