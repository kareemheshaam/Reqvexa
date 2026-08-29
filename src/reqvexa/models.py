from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class OriginType(StrEnum):
    SERVER_RESPONSE = "SERVER_RESPONSE"
    SET_COOKIE = "SET_COOKIE"
    REQUEST_DERIVED = "REQUEST_DERIVED"
    COOKIE_DERIVED = "COOKIE_DERIVED"
    STORAGE_DERIVED = "STORAGE_DERIVED"
    STATIC = "STATIC"
    USER_INPUT = "USER_INPUT"
    CLIENT_GENERATED = "CLIENT_GENERATED"
    JAVASCRIPT_GENERATED = "JAVASCRIPT_GENERATED"
    WEBCRYPTO_GENERATED = "WEBCRYPTO_GENERATED"
    WASM_GENERATED = "WASM_GENERATED"
    UNKNOWN = "UNKNOWN"


class NodeType(StrEnum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    VALUE = "VALUE"
    VALUE_VERSION = "VALUE_VERSION"
    STORAGE = "STORAGE"
    CHALLENGE = "CHALLENGE"
    ORIGIN_HYPOTHESIS = "ORIGIN_HYPOTHESIS"


class EdgeType(StrEnum):
    PRODUCES = "PRODUCES"
    CONSUMES = "CONSUMES"
    MUTATES = "MUTATES"
    DERIVES_FROM = "DERIVES_FROM"
    PRECEDES = "PRECEDES"
    REQUIRES = "REQUIRES"
    OBSERVED_IN = "OBSERVED_IN"


class DependencyCategory(StrEnum):
    OBSERVATIONAL = "OBSERVATIONAL_DEPENDENCY"
    SUPPORTED = "SUPPORTED_DEPENDENCY"
    HYPOTHETICAL = "HYPOTHETICAL_DEPENDENCY"
    VERIFIED = "VERIFIED_DEPENDENCY"


@dataclass(frozen=True)
class Header:
    name: str
    value: str
    index: int


@dataclass(frozen=True)
class Cookie:
    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    secure: bool | None = None
    host_only: bool | None = None
    partition_key: str | None = None

    def identity_scope(self) -> tuple[str, str, bool | None, bool | None, str]:
        return (self.name, self.domain or "", self.secure, self.host_only, self.partition_key or "")


@dataclass(frozen=True)
class SourceLocation:
    container: str
    path: str | None
    request_id: str | None = None
    response_id: str | None = None
    offset: int | None = None


@dataclass(frozen=True)
class HttpRequest:
    id: str
    sequence: int
    timestamp: datetime | None
    method: str
    url: str
    query: tuple[tuple[str, str], ...]
    headers: tuple[Header, ...]
    cookies: tuple[Cookie, ...]
    body: bytes | None
    body_encoding: str | None
    initiator: str | None
    response_id: str | None
    source_entry_id: str
    timing: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class HttpResponse:
    id: str
    request_id: str
    status: int
    headers: tuple[Header, ...]
    cookies: tuple[Cookie, ...]
    body: bytes | None
    mime_type: str | None
    timing: dict[str, Any] = field(default_factory=dict)
    source_entry_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Capture:
    requests: tuple[HttpRequest, ...]
    responses: tuple[HttpResponse, ...]
    source: str = "har"

    def request(self, request_id: str) -> HttpRequest:
        for request in self.requests:
            if request.id == request_id:
                return request
        raise KeyError(f"Unknown request: {request_id}")


@dataclass(frozen=True)
class ObservedValue:
    """Canonical observation, independent of semantic naming."""

    observation_id: str
    location: SourceLocation
    raw_value: str
    normalized_value: str
    timestamp: datetime | None
    sequence: int
    semantic_hints: tuple[str, ...] = ()
    representation_ids: tuple[str, ...] = ()
    transformation: str | None = None

    @property
    def semantic_hint(self) -> str | None:
        return self.semantic_hints[0] if self.semantic_hints else None

    @property
    def request_id(self) -> str | None:
        return self.location.request_id

    @property
    def response_id(self) -> str | None:
        return self.location.response_id


ValueObservation = ObservedValue


@dataclass(frozen=True)
class SemanticHypothesis:
    name: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class LogicalValue:
    value_id: str
    observation_ids: tuple[str, ...]
    semantic_hypotheses: tuple[SemanticHypothesis, ...] = ()


@dataclass(frozen=True)
class MatchEvidence:
    evidence_id: str
    method: str
    source_observation: str
    target_observation: str
    confidence: float
    explanation: str
    transformation: str | None = None


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    kind: str
    description: str
    source_ids: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class ProducerHypothesis:
    producer: str
    value_version: str
    evidence_ids: tuple[str, ...]
    confidence: float
    status: str = "CANDIDATE"
    category: DependencyCategory = DependencyCategory.OBSERVATIONAL


@dataclass(frozen=True)
class ValueVersion:
    version_id: str
    value_id: str
    value_digest: str
    display_value: str
    raw_value: str = field(repr=False)
    valid_from: int
    valid_until: int | None
    observation_ids: tuple[str, ...] = ()
    producer_hypotheses: tuple[ProducerHypothesis, ...] = ()
    consumer_ids: tuple[str, ...] = ()
    confidence: float = 1.0


@dataclass(frozen=True)
class Node:
    node_id: str
    node_type: NodeType
    label: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    edge_id: str
    source: str
    target: str
    type: EdgeType
    evidence_ids: tuple[str, ...]
    confidence: float
    inference_method: str
    category: DependencyCategory = DependencyCategory.OBSERVATIONAL


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        self.nodes[node.node_id] = node

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence[evidence.evidence_id] = evidence

    def add_edge(self, edge: Edge) -> None:
        if not edge.evidence_ids:
            raise ValueError("Inference edges require evidence")
        if any(item not in self.evidence for item in edge.evidence_ids):
            raise ValueError("All edge evidence IDs must be registered")
        self.edges[edge.edge_id] = edge

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.node_id, "type": n.node_type.value, "label": n.label, "payload": n.payload}
                for n in sorted(self.nodes.values(), key=lambda item: item.node_id)
            ],
            "edges": [
                {"id": e.edge_id, "source": e.source, "target": e.target, "type": e.type.value,
                 "evidence_ids": list(e.evidence_ids), "confidence": e.confidence,
                 "inference_method": e.inference_method, "category": e.category.value}
                for e in sorted(self.edges.values(), key=lambda item: item.edge_id)
            ],
            "evidence": [
                {"id": ev.evidence_id, "kind": ev.kind, "description": ev.description,
                 "source_ids": list(ev.source_ids), "confidence": ev.confidence}
                for ev in sorted(self.evidence.values(), key=lambda item: item.evidence_id)
            ],
        }


@dataclass(frozen=True)
class SecretDisplayPolicy:
    unsafe_raw: bool = False
    mask_length: int = 4

    def display(self, value: str) -> str:
        if self.unsafe_raw:
            return value
        if not value:
            return ""
        return value if len(value) <= self.mask_length else value[:self.mask_length] + "*" * (len(value) - self.mask_length)

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    encoded = json.dumps(parts, ensure_ascii=True, separators=(",", ":"), default=str)
    return f"{prefix}_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"
