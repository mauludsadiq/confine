# confine

`confine` is a deterministic authority boundary for an untrusted autoregressive model. The model is treated as a hostile proposal source that can emit only candidate records. Every externally meaningful state transition is parsed into a closed action algebra, checked against explicit capabilities and information-flow rules, bound to the current state by a certificate, independently re-verified against the full policy kernel at execution time, executed exactly once, committed atomically, and recorded in a hash-chained receipt.

The repository contains three things:

1. **A complete FARD v1.7.1 reference implementation** (`packages/confine/`) — an invoice-follow-up system with two independent external effect adapters (email and Slack), 27 adversarial tests, and no shell execution, raw HTTP, arbitrary SQL, arbitrary filesystem access, dynamic plugins, or model-controlled destinations.
2. **A language-neutral protocol specification** (`PROTOCOL.md`) — defining canonical encoding, hashing, HMAC, the label lattice, capability model, and executor conformance requirements independent of FARD syntax, so other languages can implement byte-identical, interoperable versions.
3. **Reference ports in Rust, Python, and JavaScript** (`ports/`) — independent implementations of the protocol's encoding, hashing, label, and capability layers, verified against real vectors captured from the FARD implementation, not re-derived from reading the spec alone.

## Security model

    Every externally observable effect must correspond to one authorized canonical action,
    independently re-verified against the full policy kernel at execution time, executed
    against the state hash that was verified, with a fresh nonce, a valid broker certificate,
    and an atomic compare-and-swap commit, and must be bound into a transition receipt.

The property that distinguishes this from a naive check-then-act system: **the executor does not trust that whoever requested a certificate ran policy verification correctly, or at all.** `executor.execute_exact` independently reruns the same deterministic policy kernel used at issuance (`policy.verify`), against the exact state and action it is about to execute, and refuses to commit anything the policy kernel itself would deny — regardless of who issued the certificate, what obligations it claims, or what the caller's environment told it was true.

Denial property:

    not Authorized(a, c)  =>  external state delta = 0

Prompt injection, jailbreaks, deceptive reasoning, or a model told (correctly or not) that it is operating without real consequences can change which proposals are emitted, but cannot enlarge the action language, bypass IFC label flow, forge obligations independent of the action they describe, race a concurrent commit onto a divergent fork, or commit a transition the policy kernel would reject — because that kernel is re-run, not assumed, at the moment of execution, and commits are serialized through an atomic compare-and-swap store.

## Repository layout

    packages/confine/         FARD reference implementation
      canonical.fard            canonical JSON, tagged hashes
      labels.fard                IFC labels, flow relation
      actions.fard                 closed action parser (5 actions)
      state.fard                    committed state, per-effect delivery tracking
      capabilities.fard              actor-operation capabilities
      policy.fard                     deterministic transition predicates;
                                        single source of truth for obligations
      certificate.fard                 HMAC-SHA256-signed, state-bound certificates
      executor.fard                     independently reruns policy.verify before commit
      commit_store.fard                  atomic CAS layer (std/mutex-backed)
      receipts.fard                       receipt generation, chain verification
      engine.fard                          parse -> verify -> certify -> execute -> receipt
      config.fard                           configuration validation
    examples/
      invoice_config.fard        reference policy, capabilities, data
      run_invoice.fard             complete draft/approve/submit flow
    tests/
      test_confine.fard             27 positive and adversarial tests
    PROTOCOL.md                       language-neutral specification (v2)
    ports/
      rust/                            confine-core: canonical encoding, hashing,
                                         HMAC, labels, capabilities (cargo test)
      python/                           confine_core: same scope (pytest)
      js/                                same scope (node --test)

## Actions

The only representable actions are `read_invoice`, `create_draft`, `approve_draft`, `submit_draft`, and `post_to_slack`. Email submission and Slack posting are deterministic effect records (`email_submission`, `slack_message`) in committed state. A production deployment connects those exact records to separately isolated adapters. The model never receives credentials or a network capability, and each adapter must accept only its own verified effect schema. Unknown action tags and unknown fields are both rejected at parse.

## Information-flow control

Labels have the form `{ kind, owner, compartments }`. Implemented kinds: `public`, `internal`, `customer`, `secret`. Customer data may flow only to a customer label with the same owner and at least the same compartments — a customer-owned draft cannot flow to an internal sink. This is enforced identically for both adapters (`create_draft`, `submit_draft`, `post_to_slack`) using the same `labels.flows_to` relation, with no adapter-specific IFC logic — proven when the Slack adapter correctly rejected a customer-to-internal flow using zero new IFC code. Slack channel identity and classification are bound together by policy (`policy.approved_slack_channels`), never trusted from the caller: a forged `channel_label` is rejected even when it would otherwise be IFC-legal.

## Capabilities and separation of duties

Capabilities are actor-specific operation lists with no default-allow. `post_to_slack` is a distinct capability from `submit_draft`, so email delivery rights never implicitly grant Slack posting rights. When `require_separation_of_duties` is true, the actor that created a draft cannot approve it, even if capability configuration accidentally grants both operations.

## State binding, replay prevention, and atomic commit

Every proposal contains `expected_state_hash` and a caller-generated `nonce`, checked both by policy and independently by the executor. This closes replay within a single state lineage — but `engine.apply_with_receipt` alone is a pure function with no shared storage, so two independent callers reading the same prior state could each successfully commit, potentially consuming the same nonce on divergent forks. `commit_store.fard` closes this with real compare-and-swap: it holds state behind a `std/mutex`, and `commit()` re-checks `expected_state_hash` against the *current* stored state, not the caller's possibly-stale copy. The loser of a race is rejected with `STATE_COMMIT_CONFLICT` and must retry. This guarantees at most one of two racing commits succeeds, for callers sharing a store handle within a process — it does not provide cross-process or cross-machine atomicity; a distributed deployment needs equivalent CAS discipline at its actual persistence layer.

## Certificates

`certificate.issue` binds policy's obligations to the prior state hash, canonical action hash, actor, policy hash, capability hash, nonce, and sequence, then signs the record with `crypto.hmac_sha256`. An earlier version computed its MAC as `SHA256(secret || tag || message)` via string concatenation — a secret-prefix construction vulnerable in principle to length-extension attacks — which has been replaced with the proper keyed primitive. The broker secret is normalized to hex internally before use as the HMAC key, so callers may supply any string.

## The executor is the real authority boundary

This is the single most important property in the codebase. It was previously possible to construct a validly-signed certificate directly, bypassing `policy.verify`, whose obligations merely echoed the fields of an action that itself violated policy — an obligations-only check could never catch this. `execute_exact` now reruns `policy.verify(state, action, actor_id, capabilities, policy)` in full, immediately before every commit, and rejects with `EXECUTOR_POLICY_DENIED` if policy would deny the action — regardless of what certificate was presented. This is proven by adversarial tests constructing exactly this kind of forged-but-internally-consistent certificate for both the email and Slack paths. It also means every new action type gets this protection automatically: `post_to_slack` required zero new enforcement code in `executor.fard`.

## Running

    fardrun run --program examples/run_invoice.fard --out out/run_invoice.json
    fardrun verify --out out/run_invoice.json
    fardrun test --program tests/test_confine.fard

## Test coverage

27 tests. Core parsing/validation and policy invariants (capability denial, stale-state, nonce replay, approval requirements, receipt chain integrity) sit alongside the substance of this repository: the executor rejecting obligations that don't match their action even when internally self-consistent; certificate tampering and wrong-secret rejection via HMAC verification; the executor independently catching IFC violations and mislabeled recipients that an obligations-only check would miss; a real atomic commit store rejecting one of two racing commits; and the second adapter (`post_to_slack`) proving IFC, capability isolation, quota isolation, cross-adapter state independence, executor-level policy generalization, and forged-channel-label rejection all hold for a structurally different effect type with no adapter-specific hardening required.

## Multi-language reference ports

`PROTOCOL.md` defines the protocol independent of FARD syntax: a restricted integer-only value model (no floats — they're the largest source of cross-language hash divergence), exact canonical encoding rules, byte-level tagged-digest and HMAC constructions, the label lattice as a formal relation, and a normative executor conformance requirement.

`ports/rust`, `ports/python`, and `ports/js` each implement the complete protocol through section 11 — canonical encoding, tagged hashing, HMAC, the label lattice, capability model, the deterministic `policy.verify` decision procedure, state hashing, certificate issuance/verification, and the executor conformance requirement — verified against real vectors captured by running the actual FARD implementation via `fardrun`, not derived from reading the specification alone.

This caught several real bugs, not hypothetical ones. During the Rust port: `certificate.fard`'s broker secret is normalized via `bytes.to_hex(bytes.of_str(secret))` before being passed to `hmac_sha256` (which hex-decodes it again), so the effective HMAC key is the raw UTF-8 bytes of the secret string, not a hex-decode of it. Separately, the real `capabilities` config has a top-level `operations` registry field that affects `capability_hash` even though `operation_allowed()` never reads it, and `approved_slack_channels` nests each channel as `{label: {...}}` rather than the label directly — both guessed wrong on the first attempt and caught immediately by a hash comparison against real output. A third failure was more subtle: individually correct `action_hash`, obligations, `capability_hash`, and `policy_hash` combined into a certificate that was internally self-consistent but signed against test fixtures incomplete relative to the real config (missing an actor, a customer, a channel, an invoice) — isolated by testing each component separately before finding the actual cause. None of these were logic bugs; all were caught only because every claim was checked against a real number instead of assumed correct.

The core adversarial case — a certificate whose obligations are internally consistent with a forged action that itself violates policy, which only an independent full policy rerun (not an obligations-only check) can catch — is proven in all three languages, using the same vector in each.

Run each port's tests independently:

    cd ports/rust && cargo test
    cd ports/python && python3 -m pytest tests/ -v
    cd ports/js && npm test

## Trusted computing base

Canonical value encoding, action parser, state hashing, label flow relation, capability lookup, policy predicates (issued once, reverified independently at execution), certificate issue/verification, exact executor dispatch, atomic commit store, receipt generation/verification, and the SHA-256/HMAC-SHA256 implementations supplied by the runtime. The model, prompt construction, retrieval, planning, natural-language rationale, and proposal generation are outside the trusted computing base.

## Explicit non-goals

`confine` does not claim to prove a business policy is morally or economically adequate, eliminate hardware/runtime/cryptographic implementation defects, eliminate every timing or resource covert channel, prevent an independently authorized human from acting outside the broker, turn an external API into a deterministic system, or provide cross-process/cross-machine commit atomicity beyond what a conforming CAS backend independently provides.

It does ensure that, within the implemented transition system, model output alone has no execution authority; rejected proposals produce no committed external effect; and no certificate — however obtained or by whom — can authorize an action the policy kernel itself would deny, because that kernel is re-run, not trusted, at the moment of execution.

## Extending safely

Do not add a generic tool interface. To add an operation: add one exact parser branch with a closed field set; define all state and IFC preconditions in `policy.fard`, expressed through `obligations_for_action` so obligations and policy decisions stay derived from one source; add actor capability assignment through configuration; add one exact executor branch — you do not need to duplicate policy checks in the executor, since `execute_exact` already reruns the full kernel for you; include the result in receipts; add positive, tampering, stale-state, replay, cross-label, capability-isolation, and quota-isolation tests. `post_to_slack` is a worked example of this process end to end.

An operation is not complete until the parser, policy, executor, receipt path, and adversarial tests all exist — and until at least one test proves the executor's independent policy rerun catches a forged certificate for that specific action, not just that the happy path works.

## License

MUI
