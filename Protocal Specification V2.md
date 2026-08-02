# The confine Protocol — Specification v2

## Status

This document defines `confine.protocol.v2`, a language-neutral specification. The FARD implementation in `packages/confine/` is one conforming implementation, not the definition of the protocol. Prior artifacts (hashes, certificates, receipts) produced by that implementation before this specification existed are tagged `confine.protocol.v1-fard` and are NOT required to be bit-compatible with v2. Do not silently reinterpret v1-fard bytes as v2; if both must be supported, they are distinct, explicitly tagged protocol versions with independent domain-separation tags.

## 1. Scope and terminology

This specification defines everything required for two independent implementations, in two different languages, to produce byte-identical canonical encodings, hashes, HMACs, certificates, and receipts given the same logical inputs — without either implementation depending on the other's runtime, and without needing a shared test harness beyond this document and its test vectors.

Terms:

- **Actor** — an identified principal (human or agent) whose proposals are subject to capability and policy checks.
- **Action** — a closed, schema-defined record describing one candidate state transition.
- **Policy** — the deterministic decision procedure mapping (state, action, actor, capabilities, policy config) to Allow(obligations) or Deny(code, data).
- **Certificate** — a signed, state-bound, action-bound authorization artifact issued after a policy Allow.
- **Executor** — the component that independently reverifies policy and commits a state transition.
- **Receipt** — a signed record binding one committed transition into a hash chain.

## 2. Protocol value model

The protocol value domain — i.e., anything that participates in canonical encoding, hashing, or MAC computation — is restricted to:

- `null`
- `boolean` (`true` / `false`)
- signed integer, representable exactly as a 64-bit two's-complement value (`-9223372036854775808` to `9223372036854775807`)
- UTF-8 string
- array (ordered list of protocol values)
- object (unordered map with UTF-8 string keys, protocol values)

Explicitly EXCLUDED from the hashed protocol surface:

- floating-point values of any kind
- raw bytes without an explicit hex/base64 string encoding
- functions, closures, or any executable value
- error/exception values
- maps with non-string keys
- timestamps without a fixed string representation (ISO-8601 UTC string, if needed)
- any implementation-specific numeric type (bignum, decimal, etc.)

Rationale: floats are the single largest source of cross-language hash incompatibility (negative zero, exponent formatting, trailing zeros, NaN/Infinity, shortest-round-trip formatting, differing parser behavior). confine's actual domains — amounts in cents, counters, sequence numbers, policy/capability versions, hashes, identifiers, labels, quotas — are exactly representable as integers or strings. If a decimal value is ever required, it MUST be encoded structurally as `{"coefficient": <int>, "scale": <int>}` or as a canonical decimal string, never as a native float.

A conforming implementation's native runtime MAY use richer types internally, but MUST reject (at the parse boundary) any action or configuration value that cannot be exactly represented in this restricted model before it enters the hashed protocol surface.

## 3. Canonical UTF-8 encoding

Given a protocol value `v`, its canonical encoding `C(v)` is produced as follows:

- Objects: keys sorted by byte-wise ascending order of their UTF-8 encoding; no whitespace between tokens; each key-value pair as `"key":value`; pairs separated by `,`; wrapped in `{}`.
- Arrays: elements in their given order, separated by `,`, wrapped in `[]`.
- Strings: wrapped in `"`, with `"`, `\`, and control characters (U+0000–U+001F) escaped per standard JSON string escaping; all other UTF-8 bytes emitted literally (no `\uXXXX` escaping of non-ASCII characters — output is UTF-8, not ASCII-safe JSON).
- Integers: emitted as their minimal decimal ASCII representation, no leading zeros (except the literal `0`), a single leading `-` for negative values, no leading `+`.
- Booleans: `true` / `false` literal.
- `null`: `null` literal.

`C(v)` is defined to be deterministic: the same logical value always produces the same byte sequence, independent of source language, map iteration order, or original input formatting.

## 4. Hash and domain-separation constructions

Given a domain tag `t` (ASCII, non-empty, no embedded newline) and a protocol value `v`:

```
D(t, v) = "sha256:" ++ hex(SHA256(UTF8(t) ++ 0x0A ++ C(v)))
```

Where:
- `UTF8(t)` is the UTF-8 byte encoding of the tag string.
- `0x0A` is exactly one newline byte (not `\r\n`).
- `C(v)` is the canonical encoding defined in §3, as UTF-8 bytes.
- `hex(...)` is lowercase hexadecimal, no `0x` prefix, no separators.
- The result includes the literal `sha256:` prefix.

This is the `tagged_digest` construction. Plain `digest(v)` (no tag) is defined as `D("", v)` is NOT used in this protocol — every hash in this system MUST be tagged, to prevent cross-domain collision (e.g., an action hash being reinterpreted as a certificate hash).

Defined domain tags (v2):

| Tag | Used for |
|---|---|
| `confine.action.v2` | action hash |
| `confine.state.v2` | state hash |
| `confine.certificate.v2` | certificate digest |
| `confine.draft.v2` | draft content hash (or equivalent resource content hash) |
| `confine.body.v2` | effect body hash |
| `confine.policy.v2` | policy config digest |
| `confine.capabilities.v2` | capability config digest |

## 5. HMAC construction

Given a key `k` (raw bytes) and an unsigned certificate record `u`:

```
M(u)      = UTF8("confine.certificate.mac.v2") ++ 0x0A ++ C(u)
MAC(k, u) = "sha256:" ++ hex(HMAC-SHA256(k, M(u)))
```

**Key representation:** the HMAC key is defined as raw bytes. Configured secrets external to the protocol (e.g. `broker_secret` in configuration) are represented as lowercase hexadecimal or unpadded base64url text and MUST be decoded to raw bytes before use as the HMAC key. Plain-text secrets used directly as UTF-8 bytes are permitted only under explicit configuration flag `broker_secret_encoding: "utf8"` for backward compatibility with v1-fard-style deployments; the default and recommended encoding is `"hex"`.

`u` (the unsigned certificate) is defined in §9. `C(u)` excludes the `mac` field entirely (it is computed before the field exists, not stripped after).

## 6. Action definitions

An action type is defined by:

- a unique `t` tag (string)
- a closed, ordered set of required field names and their protocol-value types
- a parser rule: reject if any field is missing, mistyped, or if any field is present that is not in the closed set (no unknown fields, ever)

Action types are registered at configuration time, never by the model / proposal source. Every action MUST include `nonce` (string) and `expected_state_hash` (string, format `sha256:` + 64 lowercase hex characters) as part of its closed field set.

## 7. Label lattice and information-flow rules

A label is a protocol object: `{ "kind": string, "owner": string, "compartments": array<string> }`.

Defined kinds and their total order by rank: `public` (0) < `internal` (1) < `customer` (2) = `secret` (2) (customer and secret are incomparable with each other, both rank above internal).

`flows_to(source, sink)` is defined as a relation, not a function with side effects:

- `public` flows to any valid label.
- `internal` flows to any label with rank ≥ 1.
- `customer` flows to a label iff `sink.kind == "customer"`, `sink.owner == source.owner`, and `sink.compartments ⊇ source.compartments`.
- `secret` flows to a label iff `sink.kind == "secret"`, `sink.owner == source.owner`, and `sink.compartments ⊇ source.compartments`.

No other flow relation is defined. There is no default-allow case. `flows_to` MUST return false for any pair not explicitly covered above, including any label that fails structural validation.

**Declassification** is not a silent operation. Any transition that changes a value's effective label class (e.g. customer → internal) MUST be an explicit, separately named, separately policy-gated action type, never an implicit consequence of another action's execution.

## 8. Capability model

A capability configuration binds each actor to an explicit list of permitted action-type tags, plus an optional `role` string. `operation_allowed(capabilities, actor_id, action_type)` MUST return false for any actor not present in the configuration, and false for any action type not in that actor's explicit list — there is no default-allow, and no operation implicitly grants any other operation.

## 9. Policy decision procedure

`policy_verify(state, action, actor_id, capabilities, policy_config)` returns exactly one of:

- `Allow(obligations)` where `obligations` is an ordered array of protocol objects
- `Deny(code, data)` where `code` is a string and `data` is a protocol object

This function MUST be pure: given identical inputs, it MUST always return an identical result, with no reliance on wall-clock time, randomness, or any state outside its explicit parameters.

`obligations` MUST be derivable from `action` alone, or from `(state, action)` if the obligation legitimately depends on state (e.g. echoing a resource's current label). There is exactly one function that derives obligations for a given action type — it MUST be the same function called during issuance (§9) and during independent reverification (§10). Two different obligation-derivation code paths for the same action type is a protocol violation.

## 10. Certificate issuance and verification

An unsigned certificate `u` is the protocol object:

```
{
  "t": "transition_certificate",
  "version": 2,
  "prior_state_hash": D("confine.state.v2", state),
  "action_hash": D("confine.action.v2", action),
  "actor_id": actor_id,
  "policy_hash": D("confine.policy.v2", policy_config),
  "capability_hash": D("confine.capabilities.v2", capabilities),
  "nonce": action.nonce,
  "sequence": state.sequence,
  "obligations": obligations
}
```

Issuance: `certificate = u ++ { "mac": MAC(key, u) }`.

Verification, given a presented `certificate`, current `state`, `action`, `actor_id`, `capabilities`, `policy_config`, and `key`:

1. `certificate` MUST contain a `mac` field, else reject (`CERTIFICATE_MISSING_MAC`).
2. Let `u' = certificate` with `mac` removed. Reject if `certificate.mac != MAC(key, u')` (`CERTIFICATE_MAC_MISMATCH`).
3. Reject if any of `prior_state_hash`, `action_hash`, `actor_id`, `policy_hash`, `capability_hash`, `nonce`, `sequence` does not exactly equal the independently recomputed value from the current `state`/`action`/`actor_id`/`capabilities`/`policy_config` presented to the verifier (not from the certificate's own claimed values) — each with its own distinct error code.

A certificate that passes verification proves only that a party holding `key` signed this exact tuple. It does NOT prove that `policy_verify` was ever correctly invoked. See §11.

## 11. Executor conformance requirements (normative)

> A conforming executor MUST independently invoke the complete policy decision procedure (`policy_verify`, §9) over the exact current state, canonical action, actor identity, capability set, and policy object, immediately before committing any effect. A certificate, its obligations, or any previously computed policy result MUST NOT substitute for this invocation.

Concretely, `execute(state, action, actor_id, capabilities, policy_config, certificate, key)`:

1. Verify the certificate per §10. Reject on any failure.
2. Independently call `decision = policy_verify(state, action, actor_id, capabilities, policy_config)`. If `decision` is `Deny`, reject with `EXECUTOR_POLICY_DENIED` and the underlying deny code — regardless of what the certificate's `obligations` field claims.
3. Reject if `C(certificate.obligations) != C(decision.obligations)` (`CERTIFICATE_OBLIGATION_MISMATCH`).
4. Reject if `action.nonce` is already present in `state`'s consumed-nonce set (`NONCE_REPLAY_AT_EXECUTOR`).
5. Only then dispatch to the exact, pure state-transition function for `action.t`.

**Mandatory negative conformance test:** a conforming implementation MUST include a test that issues a certificate directly (bypassing `policy_verify`) for an action whose fields are internally self-consistent with fabricated obligations, but which `policy_verify` would deny (e.g., an information-flow violation). The executor MUST reject this via step 2 above. An implementation that only checks step 3 in isolation (obligations-echo matching) without step 2 (full independent policy re-invocation) does NOT conform to this specification, even if it passes a naive obligations-tampering test.

## 12. Atomic commit / CAS contract

A conforming commit layer exposes:

```
commit(store, expected_state_hash, action, actor_id, capabilities, policy_config, key)
  -> Committed(new_state, receipt) | Conflict(expected, actual) | Rejected(reason)
```

`commit` MUST be atomic with respect to concurrent callers sharing the same `store`: given two concurrent calls with `expected_state_hash` computed against the same prior state, AT MOST ONE call may return `Committed`. The other MUST return `Conflict` if the state has since moved, re-exposing the actual current state hash so the caller can re-derive and retry.

This specification defines the interface, not the backing implementation. A single-process mutex-backed store, a database transaction, and a distributed consensus system (Raft, etcd, FoundationDB) are all valid conforming backends provided they satisfy the at-most-one-winner property above. Cross-process/cross-machine atomicity is only guaranteed if the backing store itself provides it — this specification does not itself provide distributed consensus.

## 13. Receipt creation and chain verification

A receipt binds:

```
{
  "previous_receipt_hash": string,
  "prior_state_hash": string,
  "action_hash": string,
  "actor_id": string,
  "certificate_hash": D("confine.certificate.v2", certificate),
  "result_hash": D(<result-specific tag>, result),
  "resulting_state_hash": string,
  "nonce": string,
  "sequence_before": integer,
  "sequence_after": integer
}
```

`receipt_hash = D("confine.receipt.v2", receipt)`.

Chain verification over an ordered list of receipts `[r_0, r_1, ..., r_n]` MUST check, for each `i > 0`:

- `r_i.previous_receipt_hash == D("confine.receipt.v2", r_{i-1})`
- `r_i.prior_state_hash == r_{i-1}.resulting_state_hash`
- `r_i.sequence_before == r_{i-1}.sequence_after`
- no `nonce` value repeats across the entire chain

and for `r_0`, `previous_receipt_hash` MUST equal the configured genesis value (64 zero bytes, hex-encoded, `sha256:` prefixed, by convention).

## 14. Error-code semantics

Error codes are protocol-visible strings, not free-form implementation messages. A conforming implementation MUST use the exact code strings defined in this specification for the conditions listed in §10–§13 (e.g. `CERTIFICATE_MAC_MISMATCH`, `EXECUTOR_POLICY_DENIED`, `STATE_COMMIT_CONFLICT`). Action-type-specific policy deny codes (e.g. `IFC_INVOICE_TO_BODY`) are defined per action type at registration time and are not enumerated here.

## 15. Conformance test vectors

Vectors are normative. Each SHOULD include every intermediate representation, not merely the final digest, so a divergence is diagnosable (parsing vs. canonicalization vs. UTF-8 encoding vs. domain separation vs. cryptography).

### Vector: primitive SHA-256 (confirmed against fardrun v1.7.0, std/hash.sha256_text)

```json
{
  "name": "primitive-sha256-001",
  "input_text": "hello",
  "sha256_hex": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "digest_text": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}
```

Note: this is a plain SHA-256 of UTF-8 "hello" with no domain tag and no newline separator — it validates the underlying hash primitive only, not the tagged_digest construction. Confirmed empirically against fardrun v1.7.0's `std/hash.sha256_text`.

### Vector: primitive HMAC-SHA256 (confirmed against fardrun v1.7.0, std/crypto.hmac_sha256)

```json
{
  "name": "primitive-hmac-sha256-001",
  "key_hex": "30313233343536373839616263646566303132333435363738396162636465",
  "key_hex_note": "hex encoding of the ASCII string 0123456789abcdef0123456789abcdef, i.e. the key argument passed to hmac_sha256 was itself already a hex string per fardrun's API contract -- confirm against your implementation whether the key argument is raw bytes or a hex string at the call boundary before treating this vector as authoritative",
  "message_text": "hello",
  "hmac_hex": "1a0927a7ed7a365b7aa0eb128475351ad288913644d26507f115accac23aa5d6"
}
```

**OPEN ITEM:** this vector was captured empirically (see conversation history: `crypto.hmac_sha256("0123456789abcdef0123456789abcdef", "hello")`), but the exact byte-level interpretation of fardrun's `hmac_sha256` key argument (raw bytes vs. hex-decoded-from-string vs. UTF-8-bytes-of-the-string) was not independently isolated as its own test — it was only confirmed indirectly via `bytes.of_str` + `bytes.to_hex` round-tripping successfully in `certificate.fard`. Before this vector is treated as normative, run an isolated test confirming whether fardrun's `hmac_sha256(k, m)` treats `k` as (a) raw UTF-8 bytes of the string, or (b) a hex-encoded string that gets decoded first. This materially changes what "key raw bytes" means in §5 and MUST be resolved before a second-language implementation attempts to match this vector.

### Vector: tagged action digest — NOT YET GENERATED

A full `confine.action.v2`-tagged digest vector, and a full certificate MAC vector using the exact §4/§5 byte construction, have not yet been generated against a real implementation. This is the next required step before this specification can be used to validate a second-language port — see §16.

## 16. Versioning and compatibility rules

- Every hash and MAC in this protocol is domain-separated by an explicit, versioned tag (`confine.*.v2`). Changing any byte-level rule in §3–§5 requires a new tag version; it is a protocol violation to change encoding behavior beneath an existing tag.
- `v1-fard` artifacts (produced before this specification existed) are not required to satisfy this document and MUST NOT be silently reinterpreted as `v2`.
- A future `v3` MAY be defined; this document does not commit to `v2` being final.

## 17. Security assumptions and non-guarantees (see also README.md)

This specification defines byte-level and procedural conformance. It does NOT itself guarantee: correctness of a particular deployment's business policy; freedom from hardware, runtime, or cryptographic implementation defects; freedom from timing or resource covert channels; prevention of an independently authorized human from acting outside the system entirely; or cross-process/cross-machine commit atomicity beyond what a conforming CAS backend (§12) independently provides.

---

**STATUS OF THIS DOCUMENT: DRAFT.** Sections 15's open item (HMAC key byte-level semantics) must be resolved with an isolated empirical test before any second-language implementation begins, or the very first cross-language vector comparison will fail for a reason unrelated to the actual port's correctness.
