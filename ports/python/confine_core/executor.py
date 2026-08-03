"""Executor conformance (spec PROTOCOL.md sec 11) -- the normative
invariant this entire project is built around.

A conforming executor MUST independently invoke the complete policy
decision procedure over the exact current state, canonical action, actor
identity, capability set, and policy object, immediately before
committing any effect. A certificate, its obligations, or a previously
computed policy result MUST NOT substitute for this invocation.
"""

from .certificate import verify as certificate_verify, _obligation_to_dict
from .policy import verify as policy_verify
from .state import nonce_consumed
from .canonical import encode


class ExecuteError(Exception):
    def __init__(self, code, policy_code=None):
        self.code = code
        self.policy_code = policy_code
        super().__init__(code)


def execute_exact(state, action, actor_id, capabilities, policy, certificate, broker_secret):
    cv = certificate_verify(certificate, state, action, actor_id, capabilities, policy, broker_secret)
    if cv is not None:
        raise ExecuteError(cv.code)

    decision = policy_verify(state, action, actor_id, capabilities, policy)
    if decision["t"] == "deny":
        raise ExecuteError("EXECUTOR_POLICY_DENIED", policy_code=decision["code"])

    real_obligations = decision["obligations"]
    cert_obligations_encoded = encode([_obligation_to_dict(o) for o in certificate.obligations])
    real_obligations_encoded = encode([_obligation_to_dict(o) for o in real_obligations])
    if cert_obligations_encoded != real_obligations_encoded:
        raise ExecuteError("CERTIFICATE_OBLIGATION_MISMATCH")

    if nonce_consumed(state, action["nonce"]):
        raise ExecuteError("NONCE_REPLAY_AT_EXECUTOR")

    return {"t": "allow", "obligations": real_obligations}
