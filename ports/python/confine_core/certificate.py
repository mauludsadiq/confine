"""Certificate issuance and verification (spec PROTOCOL.md sec 10).

Direct port of packages/confine/certificate.fard, transliterated from the
vector-confirmed Rust port. Uses the v1-fard MAC construction (tag
confine.certificate.mac.v1, key = raw UTF-8 bytes of the broker_secret
string) matching current real fardrun behavior.
"""

from dataclasses import dataclass, field
from .hash import certificate_mac_v1_fard
from .state import hash_state
from .capabilities import digest as capability_digest
from .policy import digest as policy_digest


def _label_to_dict(label):
    return {"kind": label.kind, "owner": label.owner, "compartments": list(label.compartments)}


def _action_to_dict(action: dict) -> dict:
    """Actions are plain dicts with FARD field names already, except any
    Label dataclass values (body_label, recipient_label, channel_label)
    need conversion before canonical encoding."""
    out = {}
    for k, v in action.items():
        out[k] = _label_to_dict(v) if hasattr(v, "kind") and hasattr(v, "owner") else v
    return out


def action_hash(action: dict) -> str:
    from .hash import tagged_digest
    return tagged_digest("confine.action.v1", _action_to_dict(action))


def _obligation_to_dict(o: dict) -> dict:
    out = dict(o)
    if "label" in out and hasattr(out["label"], "kind"):
        out["label"] = _label_to_dict(out["label"])
    return out


@dataclass
class Certificate:
    prior_state_hash: str
    action_hash: str
    actor_id: str
    policy_hash: str
    capability_hash: str
    nonce: str
    sequence: int
    obligations: list
    mac: str = ""


def _unsigned_dict(cert: Certificate) -> dict:
    return {
        "t": "transition_certificate",
        "version": 1,
        "prior_state_hash": cert.prior_state_hash,
        "action_hash": cert.action_hash,
        "actor_id": cert.actor_id,
        "policy_hash": cert.policy_hash,
        "capability_hash": cert.capability_hash,
        "nonce": cert.nonce,
        "sequence": cert.sequence,
        "obligations": [_obligation_to_dict(o) for o in cert.obligations],
    }


def issue(state, action, actor_id, capabilities, policy, obligations, broker_secret) -> Certificate:
    unsigned = Certificate(
        prior_state_hash=hash_state(state),
        action_hash=action_hash(action),
        actor_id=actor_id,
        policy_hash=policy_digest(policy),
        capability_hash=capability_digest(capabilities),
        nonce=action["nonce"],
        sequence=state.sequence,
        obligations=obligations,
    )
    mac = certificate_mac_v1_fard(broker_secret, _unsigned_dict(unsigned))
    unsigned.mac = mac
    return unsigned


class VerifyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def verify(certificate: Certificate, state, action, actor_id, capabilities, policy, broker_secret):
    if not certificate.mac:
        return VerifyError("CERTIFICATE_MISSING_MAC")
    expected_mac = certificate_mac_v1_fard(broker_secret, _unsigned_dict(certificate))
    if certificate.mac != expected_mac:
        return VerifyError("CERTIFICATE_MAC_MISMATCH")
    if certificate.prior_state_hash != hash_state(state):
        return VerifyError("CERTIFICATE_STATE_MISMATCH")
    if certificate.action_hash != action_hash(action):
        return VerifyError("CERTIFICATE_ACTION_MISMATCH")
    if certificate.actor_id != actor_id:
        return VerifyError("CERTIFICATE_ACTOR_MISMATCH")
    if certificate.policy_hash != policy_digest(policy):
        return VerifyError("CERTIFICATE_POLICY_MISMATCH")
    if certificate.capability_hash != capability_digest(capabilities):
        return VerifyError("CERTIFICATE_CAPABILITY_MISMATCH")
    if certificate.nonce != action["nonce"]:
        return VerifyError("CERTIFICATE_NONCE_MISMATCH")
    if certificate.sequence != state.sequence:
        return VerifyError("CERTIFICATE_SEQUENCE_MISMATCH")
    return None
