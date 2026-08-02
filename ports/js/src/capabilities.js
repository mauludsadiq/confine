// Capability model (spec PROTOCOL.md sec 8).
//
// Direct port of packages/confine/capabilities.fard's operation_allowed().
// No default-allow: an actor absent from the map, or an operation absent
// from that actor's explicit list, returns false.

export function operationAllowed(capabilities, actorId, operation) {
  const actor = capabilities.actors[actorId];
  if (!actor) return false;
  return actor.operations.includes(operation);
}

export function actorRole(capabilities, actorId) {
  const actor = capabilities.actors[actorId];
  return actor ? actor.role : null;
}
