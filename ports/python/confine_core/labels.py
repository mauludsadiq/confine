"""Label lattice and information-flow rules (spec PROTOCOL.md sec 7).

Direct port of packages/confine/labels.fard. Verified against 12 real
flows_to() truth-table vectors captured from fardrun v1.7.0.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Label:
    kind: str
    owner: str
    compartments: tuple


def public_label() -> Label:
    return Label(kind="public", owner="*", compartments=())


def internal_label() -> Label:
    return Label(kind="internal", owner="organization", compartments=())


def customer_label(customer_id: str) -> Label:
    return Label(kind="customer", owner=customer_id, compartments=("customer_data",))


def secret_label(secret_id: str) -> Label:
    return Label(kind="secret", owner=secret_id, compartments=("secret",))


def _rank(kind: str) -> int:
    return {"public": 0, "internal": 1, "customer": 2, "secret": 3}.get(kind, 100)


def _valid(label: Label) -> bool:
    return _rank(label.kind) < 100


def _contains_all(xs, ys) -> bool:
    return all(y in xs for y in ys)


def flows_to(source: Label, sink: Label) -> bool:
    """Direct port of labels.fard's flows_to(). Branch order matches source."""
    if not _valid(source) or not _valid(sink):
        return False
    if source.kind == "public":
        return True
    if source.kind == "internal":
        return _rank(sink.kind) >= 1
    if source.kind == "customer":
        return (
            sink.kind == "customer"
            and source.owner == sink.owner
            and _contains_all(sink.compartments, source.compartments)
        )
    if source.kind == "secret":
        return (
            sink.kind == "secret"
            and source.owner == sink.owner
            and _contains_all(sink.compartments, source.compartments)
        )
    return False
