# confine

`confine` is a deterministic authority boundary for an untrusted autoregressive model. The model is not treated as an operator inside a cage. It is treated as a hostile proposal source that can emit only candidate records. Every externally meaningful state transition is parsed into a closed action algebra, checked against explicit capabilities and information-flow rules, bound to the current state by a certificate, executed exactly once, and recorded in a hash-chained receipt.

This repository contains a complete invoice-follow-up reference implementation in FARD v1.7.1. It does not expose shell execution, raw HTTP, arbitrary SQL, arbitrary filesystem access, dynamic plugins, or model-controlled destinations. The only representable actions are:

- `read_invoice`
- `create_draft`
- `approve_draft`
- `submit_draft`

The external submission is represented as a deterministic `email_submission` effect in committed state. A production deployment connects that exact effect record to a separately isolated email adapter. The model never receives credentials or a network capability, and the adapter must accept only the verified effect schema.

## Security model

The central invariant is:

```text
Every externally observable effect must correspond to one authorized canonical action,
executed against the state hash that was verified, with a fresh nonce and a valid
broker certificate, and must be bound into a transition receipt.
```

Formally:

```text
ExternallyObservable(e)
  => exists a, c, r:
       Authorized(a, c)
       and ExecutedExactly(a)
       and ReceiptBinds(r, e)
```

The denial property is:

```text
not Authorized(a, c) => external state delta = 0
```

`confine` moves the trust boundary away from model behavior. Prompt injection, jailbreaks, adversarial fine-tuning, deceptive reasoning, or malformed model output can change which proposals are emitted, but cannot enlarge the action language or the set of transitions accepted by policy.

## Architecture

```text
Untrusted model bytes
        |
        v
Strict action parser
  - closed tags
  - exact fields
  - type checks
  - no unknown fields
        |
        v
Deterministic policy kernel
  - state-hash freshness
  - capabilities
  - IFC labels
  - recipient binding
  - quotas
  - separation of duties
  - nonce replay prevention
        |
        v
Transition certificate
  - action hash
  - prior state hash
  - policy hash
  - capability hash
  - actor
  - nonce
  - sequence
  - obligations
  - secret-bound MAC
        |
        v
Exact executor
  - verifies certificate again
  - no natural-language interpretation
  - one implementation per action tag
  - atomic state transition
        |
        v
Transition receipt
  - prior/resulting state hashes
  - action/certificate/result hashes
  - previous receipt hash
  - nonce and sequence
```

## Repository layout

```text
packages/confine/
  canonical.fard       canonical JSON, tagged hashes, strict field helpers
  labels.fard          IFC labels, flow relation, label join
  actions.fard         closed action parser and action hashing
  state.fard           committed state and state hashing
  capabilities.fard    actor-operation capabilities
  policy.fard          deterministic transition predicates
  certificate.fard     state-bound, action-bound broker certificates
  executor.fard        exact action implementations
  receipts.fard        receipt generation, verification, chain verification
  engine.fard          parse -> verify -> certify -> execute -> receipt
  config.fard          full configuration validation
examples/
  invoice_config.fard  supplied reference policy and data
  run_invoice.fard     complete draft/approve/submit flow
 tests/
  test_confine.fard    positive and adversarial tests
```

## No ambient authority

The model-facing boundary accepts a record. It does not expose functions equivalent to:

```text
shell(command)
http_request(method, url, body)
execute_sql(query)
read_file(path)
send_email(to, subject, body)
```

Unknown action tags are rejected. Unknown fields are rejected. This prevents a model from smuggling a second interpretation into a permissive object.

For example, this proposal is rejected during parsing:

```fard
{ t: "shell", command: "whoami" }
```

This is also rejected because `command` is not part of `read_invoice`:

```fard
{
  t: "read_invoice",
  invoice_id: "inv_001",
  nonce: "nonce-read-0001",
  expected_state_hash: "sha256:...",
  command: "hidden"
}
```

## Configuration

Policy, identities, recipients, quotas, capabilities, invoice data, thread data, and broker secret are supplied as configuration. The kernel does not contain customer identities, addresses, limits, or secrets.

A valid configuration contains:

```fard
{
  broker_secret: secret_from_runtime,
  policy_version: "invoice-policy-v1",
  policy: {
    version: "invoice-policy-v1",
    min_nonce_length: 12,
    max_draft_chars: 2000,
    max_total_drafts: 100,
    max_total_submissions: 20,
    approver_role: "approver",
    require_separation_of_duties: true,
    approved_recipients: {
      cust_001: ["billing@example.test"]
    }
  },
  capabilities: {
    operations: {
      read_invoice: true,
      create_draft: true,
      approve_draft: true,
      submit_draft: true
    },
    actors: {
      drafter_1: {
        role: "drafter",
        operations: ["read_invoice", "create_draft"]
      },
      approver_1: {
        role: "approver",
        operations: ["read_invoice", "approve_draft", "submit_draft"]
      }
    }
  },
  invoices: { ... },
  threads: { ... }
}
```

`config.validate` rejects missing policy fields, malformed capabilities, absent state data, and secrets shorter than 32 characters.

The example contains a visible development secret only so the program can be run directly. Production code must obtain the broker secret from a process boundary unavailable to the model and must never put it in prompts, model context, logs, proposals, or receipts.

## Canonical actions

The parser creates one typed record shape for each action and rejects all additional fields. The same parsed record is hashed, verified, certified, and passed to the executor. The executor never reparses model text.

The action hash is:

```text
SHA256("confine.action.v1\n" || canonical_json(action))
```

Canonical JSON is provided by `std/json.canonicalize`, so record-key order cannot produce two hashes for the same FARD value.

## Information-flow control

Labels have this form:

```fard
{
  kind: "customer",
  owner: "cust_001",
  compartments: ["customer_data"]
}
```

Implemented label classes are:

- `public`
- `internal`
- `customer`
- `secret`

Customer data may flow only to a customer label with the same owner and at least the same compartments. Therefore data labeled for `cust_001` cannot be placed in a draft or recipient sink labeled for `cust_002`.

The draft transition checks both structural identity and IFC:

```text
invoice.customer_id == action.customer_id
thread.customer_id == action.customer_id
invoice.label flows_to action.body_label
action.body_label.owner == action.customer_id
```

Submission checks:

```text
recipient is listed under draft.customer_id
recipient_label.owner == draft.customer_id
draft.body_label flows_to recipient_label
```

No silent declassification operation exists.

## Capabilities and separation of duties

Capabilities are actor-specific operation lists. An actor without `approve_draft` cannot reach approval logic at all. Approval additionally requires the role configured by `policy.approver_role`.

When `require_separation_of_duties` is true, the actor that created a draft cannot approve the same draft even if capability configuration accidentally grants both operations.

The approval is bound to the exact draft hash. Submission references that same hash. Altering any body field creates a different draft hash and therefore has no approval.

## State binding and replay prevention

Every proposal contains:

```fard
expected_state_hash: state.hash_state(current_state)
nonce: "caller-generated-unique-value"
```

Policy rejects a proposal if the expected hash does not equal the current committed state. The executor verifies the certificate against the same state again. This closes the gap between policy checking and execution.

Consumed nonces are stored in committed state. Reusing a nonce is rejected by policy and independently checked by the executor.

Every successful transition increments the state sequence exactly once.

## Certificates

The policy kernel returns obligations rather than a bare Boolean. `certificate.issue` binds those obligations to:

- prior state hash
- canonical action hash
- actor identity
- policy hash
- capability hash
- nonce
- state sequence

The certificate includes a secret-bound digest:

```text
SHA256(
  "confine.certificate.mac.v1\n"
  || broker_secret
  || "\n"
  || canonical_json(unsigned_certificate)
)
```

This construction keeps the dependency surface limited to the documented FARD SHA-256 primitive. For a deployment with a confirmed byte/text contract for `std/crypto.hmac_sha256`, replace this function with HMAC-SHA-256 while preserving all bound fields. The current implementation is complete and tamper-detecting under the assumption that the broker secret remains unavailable to the proposal source, but HMAC is the preferred production primitive.

The executor recomputes and verifies the certificate before dispatching.

## Execution semantics

All four action implementations are complete:

### `read_invoice`

Returns the exact invoice status, amount, customer identity, and label. It consumes the nonce and advances sequence state.

### `create_draft`

Checks customer/thread/invoice binding and IFC, derives a content-addressed draft hash, writes the draft to committed state, consumes the nonce, and increments the draft counter.

### `approve_draft`

Checks actor role, separation of duties, exact draft existence, and duplicate approval. It stores an approval keyed by draft hash.

### `submit_draft`

Requires an existing approval for the exact draft hash, verifies the configured recipient and IFC sink, prevents duplicate submission, and appends one deterministic `email_submission` effect to state.

The effect is:

```fard
{
  t: "email_submission",
  recipient: recipient,
  recipient_label: label,
  thread_id: draft.thread_id,
  body: draft.body,
  body_hash: sha256_of_body,
  draft_hash: draft_hash
}
```

A real email adapter must consume only this verified record. It must not accept arbitrary URLs, headers, SMTP commands, templates, file attachments, or model-generated credentials.

## Receipts

Every committed action generates a receipt binding:

```fard
{
  previous_receipt_hash,
  prior_state_hash,
  action_hash,
  actor_id,
  certificate_hash,
  result_hash,
  resulting_state_hash,
  nonce,
  sequence_before,
  sequence_after
}
```

`receipts.verify` recomputes the receipt hash and verifies sequence advancement.

`receipts.verify_chain` verifies:

- every individual receipt hash
- `current.previous_receipt_hash == previous.receipt_hash`
- `current.prior_state_hash == previous.resulting_state_hash`
- sequence continuity
- nonce uniqueness across the chain

This directly tests the receipt layer rather than assuming that receipt generation implies verification correctness.

## Running

From the repository root containing `fardrun`:

```sh
fardrun run --program confine/examples/run_invoice.fard
```

Run tests with the test command used by your FARD checkout. In repositories where tests are ordinary FARD programs discovered by the project runner, include:

```text
confine/tests/test_confine.fard
```

The test file uses only the grammar and standard-library functions listed in the supplied FARD v1.7.1 reference.

## Test coverage

The suite checks:

1. configuration validation
2. genuine transition and receipt acceptance
3. unknown action rejection
4. unknown-field rejection
5. cross-customer IFC rejection
6. capability denial
7. stale-state rejection
8. nonce replay rejection
9. approval requirement
10. unapproved-recipient rejection
11. valid three-transition receipt chain
12. tampered receipt rejection
13. broken receipt chain rejection

## Trusted computing base

The trusted core consists of:

- canonical value encoding
- action parser
- state hashing
- label flow relation
- capability lookup
- policy predicates
- certificate issue/verification
- exact executor dispatch
- receipt generation/verification
- SHA-256 implementation supplied by the runtime

The model, prompt construction, retrieval, planning, natural-language rationale, and proposal generation are outside the trusted computing base.

## Deployment requirements

A production deployment should preserve these boundaries:

1. Run the model in a microVM with no network, no persistent storage, bounded output, bounded CPU/memory, and no secrets.
2. Send model output to the parser through one bounded channel.
3. Run the policy kernel and broker outside the model VM.
4. Store the broker secret outside the model context and model filesystem.
5. Put each real external adapter in a separate process or microVM with only its own credentials.
6. Require adapters to accept only canonical verified effect records.
7. Append receipts to durable, append-only storage.
8. Pin policy and capability hashes during deployment.
9. Render canonical actions—not model prose—for human approval.
10. Sign the exact action or draft hash when human approval is required.

## Explicit non-goals

`confine` does not claim to:

- prove that a business policy is morally or economically adequate
- eliminate hardware, runtime, or cryptographic implementation defects
- eliminate every timing or resource covert channel
- prevent an independently authorized human from acting outside the broker
- turn an external API into a deterministic system

It does ensure that, within the implemented transition system, model output alone has no execution authority and rejected proposals produce no committed external effect.

## Extending safely

Do not add a generic tool interface. To add an operation:

1. Add one exact parser branch with a closed field set.
2. Define all state and IFC preconditions in `policy.fard`.
3. Add actor capability assignment through configuration.
4. Issue obligations that bind destination and effect class.
5. Add one exact executor branch.
6. Include the result in receipts.
7. Add positive, tampering, stale-state, replay, cross-label, and sequence-composition tests.

An operation is not complete until the parser, policy, executor, receipt path, and adversarial tests all exist.

## License

This package is supplied as source for integration into the FARD ecosystem. Add the license appropriate to the containing repository before redistribution.
