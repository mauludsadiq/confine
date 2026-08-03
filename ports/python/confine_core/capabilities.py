"""Capability model (spec PROTOCOL.md sec 8).

Direct port of packages/confine/capabilities.fard's operation_allowed().
No default-allow: an actor absent from the map, or an operation absent
from that actor's explicit list, returns False.
"""

from dataclasses import dataclass, field


@dataclass
class Actor:
    role: str
    operations: list


@dataclass
class Capabilities:
    actors: dict
    operations_registry: dict = None  # populated separately; see digest()

    def __post_init__(self):
        if self.operations_registry is None:
            self.operations_registry = {}

    def to_dict(self):
        return {
            "actors": {k: {"role": v.role, "operations": list(v.operations)} for k, v in self.actors.items()},
            "operations": dict(sorted(self.operations_registry.items())),
        }


def operation_allowed(capabilities: Capabilities, actor_id: str, operation: str) -> bool:
    actor = capabilities.actors.get(actor_id)
    if actor is None:
        return False
    return operation in actor.operations


def actor_role(capabilities: Capabilities, actor_id: str):
    actor = capabilities.actors.get(actor_id)
    return actor.role if actor else None


def digest(capabilities: Capabilities) -> str:
    from .hash import tagged_digest
    return tagged_digest("confine.capabilities.v1", capabilities.to_dict())
