// Label lattice and information-flow rules (spec PROTOCOL.md sec 7).
//
// Direct port of packages/confine/labels.fard. Verified against 12 real
// flows_to() truth-table vectors captured from fardrun v1.7.0.

export function publicLabel() {
  return { kind: "public", owner: "*", compartments: [] };
}

export function internalLabel() {
  return { kind: "internal", owner: "organization", compartments: [] };
}

export function customerLabel(customerId) {
  return { kind: "customer", owner: customerId, compartments: ["customer_data"] };
}

export function secretLabel(secretId) {
  return { kind: "secret", owner: secretId, compartments: ["secret"] };
}

function rank(kind) {
  switch (kind) {
    case "public": return 0;
    case "internal": return 1;
    case "customer": return 2;
    case "secret": return 3;
    default: return 100;
  }
}

function valid(label) {
  return rank(label.kind) < 100;
}

function containsAll(xs, ys) {
  return ys.every((y) => xs.includes(y));
}

// Direct port of labels.fard's flows_to(). Branch order matches source.
export function flowsTo(source, sink) {
  if (!valid(source) || !valid(sink)) return false;
  switch (source.kind) {
    case "public":
      return true;
    case "internal":
      return rank(sink.kind) >= 1;
    case "customer":
      return (
        sink.kind === "customer" &&
        source.owner === sink.owner &&
        containsAll(sink.compartments, source.compartments)
      );
    case "secret":
      return (
        sink.kind === "secret" &&
        source.owner === sink.owner &&
        containsAll(sink.compartments, source.compartments)
      );
    default:
      return false;
  }
}
