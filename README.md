# confine

`confine` is a deterministic authority boundary for an untrusted autoregressive model. The model is treated as a hostile proposal source that can emit only candidate records. Every externally meaningful state transition is parsed into a closed action algebra, checked against explicit capabilities and information-flow rules, bound to the current state by a certificate, independently re-verified against the full policy kernel at execution time, executed exactly once, committed atomically, and recorded in a hash-chained receipt.

This repository is a complete invoice-follow-up reference implementation in FARD v1.7.1, with two independent external effect adapters (email and Slack) proving the architecture generalizes rather than being coupled to one delivery channel. It exposes no shell execution, raw HTTP, arbitrary SQL, arbitrary filesystem access, dynamic plugins, or model-controlled destinations. The only representable actions are:

- `read_invoice`
- `create_draft`
- `approve_draft`
- `submit_draft`
- `post_to_slack`

Email submission and Slack posting are deterministic effect records (`email_submission`, `slack_message`) in committed state. A production deployment connects those exact records to separately isolated adapters. The model never receives credentials or a network capability, and each adapter must accept only its own verified effect schema.

## Security model

    Every externally observable effect must correspond to one authorized canonical action,
    independently re-verified against the full policy kernel at execution time, executed
    against the state hash that was verified, with a fresh nonce, a valid broker certificate,
    and an atomic compare-and-swap commit, and must be bound into a transition receipt.

The property that distinguishes this from a naive check-then-act system: **the executor does not trust that whoever requested a certificate ran policy verification correctly, or at all.** `executor.execute_exact` independently reruns the same deterministic policy kernel used at issuance (`policy.verify`), against the exact state and action it is about to execute, and refuses to commit anything the policy kernel itself would deny — regardless of who issued the certificate, what obligations it claims, or what the caller's environment told it was true.

Denial property:

    not Authorized(a, c)  =>  external state delta = 0

Prompt injection, jailbreaks, deceptive reasoning, or a model told (correctly or not) that it is operating without real consequences can change which proposals are emitted, but cannot enlarge the action language, bypass IFC label flow, forge obligations independent of the action they describe, race a concurrent commit onto a divergent fork, or commit a transition the policy kernel would reject — because that kernel is re-run, not assumed, at the moment of execution, and commits are serialized through an atomic compare-and-swap store.

## Architecture

    Untrusted model bytes
            |
            v
    Strict action parser (actions.fard)
      closed tags, exact fields, type checks, no unknown fields
            |
            v
    Deterministic policy kernel (policy.fard)
      state-hash freshness, capabilities, IFC labels, recipient/channel
      binding, quotas, separation of duties, nonce replay prevention
            |
            v
    Transition certificate (certificate.fard)
      action hash, prior state hash, policy hash, capability hash,
      actor, nonce, sequence, obligations, HMAC-SHA256 MAC
            |
            v
    Exact executor (executor.fard)
      verifies certificate MAC/hashes independently
      INDEPENDENTLY RERUNS THE FULL POLICY KERNEL -- not just an
      obligations echo-check -- rejecting anything policy would deny
      one implementation per action tag, atomic state transition
            |
            v
    Atomic commit store (commit_store.fard)
      holds state behind a mutex; commit() re-checks expected_state_hash
      against the CURRENT stored state, not the caller's stale copy;
      loser of a race gets STATE_COMMIT_CONFLICT and must retry
            |
            v
    Transition receipt (receipts.fard)
      prior/resulting state hashes, action/certificate/result hashes,
      previous receipt hash, nonce and sequence, hash-chained

## Repository layout

    packages/confine/
      canonical.fard       canonical JSON, tagged hashes, strict field helpers
      labels.fard           IFC labels, flow relation, label join
      actions.fard           closed action parser and action hashing (5 actions)
      state.fard              committed state, state hashing, per-effect
                                delivery tracking, slack_posts, slack_posted_total
      capabilities.fard        actor-operation capabilities
      policy.fard                deterministic transition predicates; single
                                   source of truth for obligations AND for
                                   full-decision reverification by the executor
      certificate.fard             state-bound, action-bound broker certificates;
                                     HMAC-SHA256 MAC (std/crypto.hmac_sha256)
      executor.fard                  exact action implementations; independently
                                       reruns policy.verify before every commit
      commit_store.fard                atomic CAS layer on top of the pure
                                         engine transition function
      receipts.fard                    receipt generation, verification, chain
                                         verification
      engine.fard                       parse -> verify -> certify -> execute
                                          -> receipt (pure function, no storage)
      config.fard                       full configuration validation
    examples/
      invoice_config.fard      reference policy, capabilities, and data,
                                 including approved_slack_channels
      run_invoice.fard          complete draft/approve/submit flow
    tests/
      test_confine.fard         27 positive and adversarial tests

## No ambient authority

The model-facing boundary accepts a record. It does not expose functions equivalent to `shell(command)`, `http_request(...)`, `execute_sql(query)`, `read_file(path)`, or `send_email(to, subject, body)`. Unknown action tags are rejected at parse. Unknown fields are rejected at parse. This prevents a model from smuggling a second interpretation into a permissive object.

## Information-flow control

Labels have the form:

    { kind: "customer", owner: "cust_001", compartments: ["customer_data"] }

Implemented label classes: `public`, `internal`, `customer`, `secret`. Customer data may flow only to a customer label with the same owner and at least the same compartments. `internal` and `customer`/`secret` are incomparable in one direction that matters here: a customer-owned draft cannot flow to an internal sink. This is enforced identically for both adapters — `create_draft`'s `IFC_INVOICE_TO_BODY` check and `submit_draft`'s `IFC_BODY_TO_RECIPIENT` check for email; `post_to_slack`'s `IFC_BODY_TO_CHANNEL` check for Slack — using the same `labels.flows_to` relation, with no adapter-specific IFC logic. No silent declassification operation exists anywhere in the system.

Slack channel identity and channel classification are bound together by policy, not supplied independently by the caller: `post_to_slack` resolves the authoritative channel label from `policy.approved_slack_channels` by `channel_id`, and rejects (`CHANNEL_LABEL_MISMATCH`) if the action's claimed `channel_label` does not match exactly — even if the claimed label would, on its own, be a legal IFC source.

## Capabilities and separation of duties

Capabilities are actor-specific operation lists. An actor without a given operation in their capability list cannot reach that operation's policy logic at all — `post_to_slack` is a distinct capability from `submit_draft`, tested explicitly so that email delivery rights never implicitly grant Slack posting rights. Approval additionally requires the role configured by `policy.approver_role`. When `require_separation_of_duties` is true, the actor that created a draft cannot approve the same draft even if capability configuration accidentally grants both operations. Approval is bound to the exact draft hash; submission and Slack posting both reference that same hash, so altering any body field produces a different draft hash and therefore has no approval.

## State binding, replay prevention, and atomic commit

Every proposal contains `expected_state_hash` and a caller-generated `nonce`. Policy rejects a proposal if the expected hash does not equal the current committed state. The executor verifies the certificate against the same state again, independently. Consumed nonces are stored in committed state; reuse is rejected by policy and independently checked by the executor.

This closes replay *within a single state lineage*, but `engine.apply_with_receipt` is a pure function with no shared storage — two independent callers reading the same prior state could each successfully commit against it, unaware of each other, potentially each consuming the same nonce on divergent forks. `commit_store.fard` closes this: it holds state behind a `std/mutex` and provides `commit(store, expected_state_hash, proposal, ...)`, which atomically locks, re-checks `expected_state_hash` against the *current* stored state rather than the caller's possibly-stale copy, runs the transition only if it matches, stores the result, and unlocks. The loser of a race is rejected with `STATE_COMMIT_CONFLICT` and must re-read and retry — standard optimistic concurrency control. This guarantees at most one of two racing commits against the same prior state succeeds, for callers sharing the same store handle within a process. It does not provide cross-process or cross-machine atomicity; a distributed deployment needs equivalent CAS discipline at its actual persistence layer, using this module as the reference shape for what that layer must guarantee.

## Certificates

The policy kernel returns obligations rather than a bare boolean. `certificate.issue` binds those obligations to the prior state hash, canonical action hash, actor identity, policy hash, capability hash, nonce, and state sequence, then signs the whole unsigned record with `crypto.hmac_sha256`. The broker secret is normalized to hex internally before use as the HMAC key (via `bytes.of_str` + `bytes.to_hex`), so callers may supply any string as `broker_secret` — the hex requirement is an internal implementation detail, not part of the public contract.

An earlier version of this certificate computed its MAC as `SHA256(secret || tag || message)` via string concatenation — a secret-prefix construction vulnerable in principle to length-extension attacks against Merkle-Damgard hash functions. That has been replaced with the proper keyed primitive.

## The executor is the real authority boundary

This is the single most important property in the codebase, and it was not true in an earlier version of this repository. It was previously possible to construct a validly-MAC'd certificate directly (bypassing `policy.verify`) whose `obligations` merely echoed the fields of an action that itself violated policy — for example, a `create_draft` action whose `body_label` claimed a different customer than the invoice it was drafted against, with obligations that faithfully echoed that same wrong customer, so an obligations-only check could never catch it. `execute_exact` now reruns `policy.verify(state, action, actor_id, capabilities, policy)` in full, independently, immediately before every commit. If policy would deny the action, the executor rejects it with `EXECUTOR_POLICY_DENIED`, regardless of what certificate was presented. This was proven, not just fixed by inspection: adversarial tests construct exactly this kind of forged-but-internally-consistent certificate for both the email and Slack paths, and confirm rejection. It also means every future action type gets this protection automatically, with zero adapter-specific executor code — proven by `post_to_slack`, which required no new enforcement logic in `executor.fard` at all.

## Execution semantics

**`read_invoice`** returns the exact invoice status, amount, customer identity, and label.

**`create_draft`** checks customer/thread/invoice binding and IFC, derives a content-addressed draft hash, writes the draft with a structured `deliveries` record (`{ email: { submitted: false, recipient: null }, slack: {} }`), and increments the draft counter. Delivery state is per-effect-type, not a single boolean, because that boolean becomes ambiguous the moment more than one sink exists.

**`approve_draft`** checks actor role, separation of duties, exact draft existence, and duplicate approval.

**`submit_draft`** requires an existing approval, verifies the configured recipient and IFC sink, checks `draft.deliveries.email.submitted` to prevent duplicate submission, and appends one deterministic `email_submission` effect.

**`post_to_slack`** requires an existing approval, resolves the channel from policy by `channel_id`, rejects a forged `channel_label`, checks IFC flow from `draft.body_label` to the configured channel label, checks `draft.deliveries.slack` for duplicate posting to the same channel, enforces its own quota (`max_total_slack_posts` / `slack_posted_total`, independent of email's), and appends one deterministic `slack_message` effect.

A real adapter must consume only its own verified effect record. It must not accept arbitrary URLs, headers, templates, file attachments, or model-generated credentials.

## Receipts

Every committed action generates a receipt binding previous receipt hash, prior/resulting state hashes, action/certificate/result hashes, nonce, and sequence before/after. `receipts.verify_chain` verifies every individual receipt hash, hash-chain continuity, `prior_state_hash` continuity between consecutive receipts, sequence continuity, and nonce uniqueness across the chain — testing the receipt layer directly rather than assuming generation implies verifiability.

## Running

    fardrun run --program examples/run_invoice.fard --out out/run_invoice.json
    fardrun verify --out out/run_invoice.json
    fardrun test --program tests/test_confine.fard

## Test coverage

27 tests, organized roughly by what they establish:

**Core parsing and validation:** configuration validation, unknown action rejection, unknown-field rejection, genuine transition and receipt acceptance.

**Policy invariants:** cross-customer IFC rejection, capability denial, stale-state rejection, nonce replay rejection, approval requirement, unapproved-recipient rejection, three-transition receipt chain, tampered/broken receipt chain rejection.

**Trust-boundary hardening (the substance of this repository):** the executor rejects obligations that don't match their action even when internally self-consistent; a state-dependent obligation (`read_invoice`) is proven safe only because the certificate's whole-state hash pin catches drift independently; a tampered certificate field is rejected by MAC verification; a certificate signed with the wrong broker secret is rejected; the executor independently rejects an IFC violation on `create_draft` and a mislabeled recipient on `submit_draft` that an obligations-only check would have missed; a real atomic commit store rejects one of two racing commits against the same prior state.

**Second-adapter generalization:** `post_to_slack` correctly denies a customer-labelled draft reaching an internal channel using the *existing* IFC lattice with zero Slack-specific code; capability isolation between `submit_draft` and `post_to_slack`; a genuine successful Slack post against an internal-labelled draft fixture; email and Slack quotas enforced independently in both directions; email and Slack delivery state and counters proven to update with no cross-contamination for drafts sharing a state lineage; the executor's full-policy-rerun generalizes automatically to a forged Slack certificate; a forged `channel_label` is rejected even when the claimed label would otherwise be IFC-legal.

## Trusted computing base

Canonical value encoding, action parser, state hashing, label flow relation, capability lookup, policy predicates (issued once, reverified independently at execution), certificate issue/verification, exact executor dispatch, atomic commit store, receipt generation/verification, and the SHA-256/HMAC-SHA256 implementations supplied by the runtime. The model, prompt construction, retrieval, planning, natural-language rationale, and proposal generation are outside the trusted computing base.

## Explicit non-goals

`confine` does not claim to prove a business policy is morally or economically adequate, eliminate hardware/runtime/cryptographic implementation defects, eliminate every timing or resource covert channel, prevent an independently authorized human from acting outside the broker, turn an external API into a deterministic system, or provide cross-process/cross-machine commit atomicity (the commit store's guarantee is scoped to a single process sharing one store handle).

It does ensure that, within the implemented transition system, model output alone has no execution authority; rejected proposals produce no committed external effect; and no certificate — however it was obtained or by whom — can authorize an action the policy kernel itself would deny, because that kernel is re-run, not trusted, at the moment of execution.

## Extending safely

Do not add a generic tool interface. To add an operation: add one exact parser branch with a closed field set; define all state and IFC preconditions in `policy.fard`, expressed through `obligations_for_action` so obligations and policy decisions stay derived from one source; add actor capability assignment through configuration; add one exact executor branch — you do not need to duplicate policy checks in the executor, since `execute_exact` already reruns the full kernel for you; include the result in receipts; add positive, tampering, stale-state, replay, cross-label, capability-isolation, and quota-isolation tests. `post_to_slack` is a worked example of this process end to end.

An operation is not complete until the parser, policy, executor, receipt path, and adversarial tests all exist — and until at least one test proves the executor's independent policy rerun catches a forged certificate for that specific action, not just that the happy path works.

## License

This package is supplied as source for integration into the FARD ecosystem. Add the license appropriate to the containing repository before redistribution.
