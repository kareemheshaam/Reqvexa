from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from typing import Any
from urllib.parse import unquote, urlsplit

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.extraction.candidates import decode_base64_candidate
from reqvexa.models import (
    Capture,
    DependencyCategory,
    Edge,
    EdgeType,
    Evidence,
    Graph,
    HttpResponse,
    LogicalValue,
    Node,
    NodeType,
    ProducerHypothesis,
    SecretDisplayPolicy,
    SemanticHypothesis,
    SourceLocation,
    ValueObservation,
    ValueVersion,
    stable_id,
)


@dataclass(frozen=True)
class TraceNode:
    version_id: str
    value_id: str
    status: str
    producer_ids: tuple[str, ...] = ()
    children: tuple[TraceNode, ...] = ()
    note: str | None = None


@dataclass
class Analysis:
    capture: Capture
    observations: tuple[ValueObservation, ...]
    graph: Graph
    versions: dict[str, ValueVersion]
    observations_by_id: dict[str, ValueObservation]
    request_observation_ids: dict[str, tuple[str, ...]]
    value_observation_ids: dict[str, tuple[str, ...]]
    target_producers: dict[str, tuple[ProducerHypothesis, ...]]
    negative_evidence: dict[str, tuple[str, ...]]
    logical_values: dict[str, LogicalValue]
    observation_value_ids: dict[str, str] = field(default_factory=dict)
    versions_by_value: dict[str, tuple[ValueVersion, ...]] = field(default_factory=dict)
    _versions_index: dict[str, dict[str, ValueVersion]] = field(
        default_factory=dict, repr=False
    )
    # Trace nodes are a pure function of the version id once the analysis is
    # built, so every trace entry point can safely share a single memo.
    _trace_memo: dict[str, TraceNode] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        """Index versions per logical value for O(1) temporal lookups."""
        for version in self.versions.values():
            self._versions_index.setdefault(version.value_id, {})[version.version_id] = version

    def trace(self, request_id: str) -> tuple[TraceNode, ...]:
        if request_id not in self.request_observation_ids:
            raise KeyError(f"Unknown request: {request_id}")
        request = self.capture.request(request_id)
        roots: list[TraceNode] = []
        for observation_id in self.request_observation_ids[request_id]:
            observation = self.observations_by_id[observation_id]
            version = self._version_for_observation(observation, request.sequence)
            if version is not None:
                roots.append(self.trace_version(version.version_id))
        unique_roots = {node.version_id: node for node in roots}
        return tuple(sorted(unique_roots.values(), key=lambda node: (node.value_id, node.version_id)))

    def _version_for_observation(self, observation: ValueObservation,
                                 sequence: int) -> ValueVersion | None:
        candidates = [
            version for version in self._versions_index.get(
                _logical_value_id(observation), {}
            ).values()
            if version.valid_from <= sequence
            and (version.valid_until is None or sequence < version.valid_until)
            and _values_match(version.raw_value, observation.normalized_value)
        ]
        return max(candidates, key=lambda version: version.valid_from, default=None)

    def _trace_version(self, version_id: str, memo: dict[str, TraceNode],
                       active: set[str]) -> TraceNode:
        if version_id in memo:
            return memo[version_id]
        version = self.versions[version_id]
        if version_id in active:
            return TraceNode(version_id, version.value_id, "UNKNOWN", note="CYCLE_DETECTED")
        active.add(version_id)
        hypotheses = self.target_producers.get(version_id, ())
        if not hypotheses:
            status = "UNKNOWN"
            note = "No matching value was observed in prior responses." if version_id in self.negative_evidence else None
            result = TraceNode(version_id, version.value_id, status, note=note)
        else:
            children: list[TraceNode] = []
            for hypothesis in hypotheses:
                producer_request = hypothesis.producer
                if producer_request.startswith("response_"):
                    response_id = producer_request.removeprefix("response_")
                    producer_request = self.graph.nodes[response_id].payload["request_id"]
                for observation_id in self.request_observation_ids.get(producer_request, ()):
                    observation = self.observations_by_id[observation_id]
                    child_version = self._version_for_observation(
                        observation, self.capture.request(producer_request).sequence)
                    if child_version and child_version.version_id != version_id:
                        children.append(self._trace_version(child_version.version_id, memo, active))
            status = "SUPPORTED" if any(h.status == "SUPPORTED" for h in hypotheses) else "HYPOTHETICAL"
            result = TraceNode(
                version_id, version.value_id, status,
                producer_ids=tuple(sorted({h.producer for h in hypotheses})),
                children=tuple(
                    sorted({child.version_id: child for child in children}.values(),
                           key=lambda node: node.version_id)
                ),
            )
        active.remove(version_id)
        memo[version_id] = result
        return result

    def trace_version(self, version_id: str) -> TraceNode:
        """Trace one version through the analysis-wide memo.

        Equivalent to a fresh ``_trace_version(version_id, {}, set())`` call:
        results never depend on prior memo entries, only on immutable
        analysis data, so the shared memo returns identical nodes.
        """
        return self._trace_version(version_id, self._trace_memo, set())

    def graph_dict(self) -> dict[str, Any]:
        return self.graph.to_dict()


class ProvenanceEngine:
    def analyze(self, capture: Capture, target_request_id: str | None = None,
                ignored_hints: set[str] | None = None,
                ignored_value_names: set[str] | None = None,
                progress_callback: Callable[[str, int, int, str], None] | None = None,
                cancel_event: Any | None = None,
                observation_callback: Callable[[str, int, tuple[ValueObservation, ...]], None]
                | None = None) -> Analysis:
        from reqvexa.extraction import extract_observations

        def emit(stage: str, current: int, total: int, message: str) -> None:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            if progress_callback is not None:
                progress_callback(stage, current, total, message)

        emit("start", 0, 1, "Starting analysis")
        capture_is_lazy = capture.is_lazy
        if capture_is_lazy:
            # Provenance needs every entry's content; a lazy capture pulls it
            # from the file for the duration and releases it again below.
            capture.materialize_all()
        target_sequence = (
            capture.request(target_request_id).sequence
            if target_request_id is not None else None
        )
        all_observations = extract_observations(
            capture,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
            observation_callback=observation_callback,
            max_sequence=target_sequence,
        )
        ignored = {item.lower().strip() for item in (ignored_hints or set()) if item.strip()}
        if ignored:
            all_observations = tuple(
                item for item in all_observations
                if not _ignored_observation(item, ignored)
            )
        ignored_values = {
            str(item).lower().strip() for item in (ignored_value_names or set())
            if str(item).strip()
        }
        if ignored_values:
            all_observations = _drop_named_values(all_observations, ignored_values)
        response_by_request = {response.request_id: response for response in capture.responses}
        body_texts: dict[str, str] = {}
        emit("scope", 1, 4, f"Collected {len(all_observations)} observations")
        observations = self._scope_observations(
            capture, all_observations, target_request_id, response_by_request, body_texts
        )
        emit("versions", 2, 4, "Resolving logical values and versions")
        by_id = {observation.observation_id: observation for observation in observations}
        observations_by_request: dict[str, list[ValueObservation]] = {}
        for observation in observations:
            if observation.request_id:
                observations_by_request.setdefault(observation.request_id, []).append(observation)
        request_ids = {
            request.id: tuple(observation.observation_id for observation in
                              observations_by_request.get(request.id, ())
                              if observation.response_id is None
                              and _is_state_observation(observation))
            for request in capture.requests
        }
        value_obs: dict[str, list[str]] = {}
        for observation in observations:
            if _is_state_observation(observation):
                value_obs.setdefault(_logical_value_id(observation), []).append(observation.observation_id)
        observation_value_ids = {
            observation_id: value_id for value_id, ids in value_obs.items() for observation_id in ids
        }
        logical_values = {
            value_id: LogicalValue(
                value_id=value_id,
                observation_ids=tuple(sorted(ids)),
                semantic_hypotheses=tuple(
                    SemanticHypothesis(name=hint, confidence=0.8)
                    for hint in sorted({
                        hint for observation_id in ids
                        for hint in by_id[observation_id].semantic_hints
                    })
                ),
            )
            for value_id, ids in sorted(value_obs.items())
        }
        versions = self._version_values(observations, value_obs, cancel_event)
        emit("graph", 3, 4, "Inferring producers and building graph")
        graph = Graph()
        self._add_capture_nodes(graph, capture, cancel_event)
        for value_id in sorted(value_obs):
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            graph.add_node(Node(value_id, NodeType.VALUE, _value_label(value_id), {}))
            for version_id in sorted(version_id for version_id, version in versions.items()
                                      if version.value_id == value_id):
                if cancel_event is not None and cancel_event.is_set():
                    raise AnalysisCancelled()
                version = versions[version_id]
                graph.add_node(Node(
                    version_id, NodeType.VALUE_VERSION, f"{_value_label(value_id)} {version_id}",
                    {"value_id": value_id, "value_digest": version.value_digest,
                     "display_value": SecretDisplayPolicy().display(version.raw_value),
                     "valid_from": version.valid_from, "valid_until": version.valid_until},
                ))
        producers, negative = self._infer_producers(
            capture, observations, versions, cancel_event, body_texts
        )
        self._add_edges(graph, capture, observations, versions, producers, negative, cancel_event)
        emit("complete", 4, 4, "Analysis complete")
        if capture_is_lazy:
            capture.dematerialize()
        return Analysis(capture, observations, graph, versions, by_id, request_ids,
                        {key: tuple(value) for key, value in value_obs.items()},
                        producers, negative, logical_values,
                        observation_value_ids, _index_versions_by_value(versions))

    @staticmethod
    def _scope_observations(capture: Capture,
                            observations: tuple[ValueObservation, ...],
                            target_request_id: str | None,
                            response_by_request: dict[str, HttpResponse],
                            body_texts: dict[str, str]) -> tuple[ValueObservation, ...]:
        if target_request_id is None:
            return observations
        target = capture.request(target_request_id)
        request_observations: dict[str, list[ValueObservation]] = {}
        for item in observations:
            if item.request_id is not None:
                request_observations.setdefault(item.request_id, []).append(item)

        selected_requests = {target_request_id}
        selected_values = {
            _logical_value_id(item)
            for item in request_observations.get(target_request_id, ())
            if _is_state_observation(item)
        }
        selected_raw_values = {
            item.normalized_value
            for item in request_observations.get(target_request_id, ())
            if _is_state_observation(item)
        }
        # Expand backwards by logical value. Once a request is relevant, all
        # of its state values become relevant too, including client-origin
        # values that may remain unresolved.
        changed = True
        while changed:
            changed = False
            for request in capture.requests:
                if request.sequence > target.sequence or request.id in selected_requests:
                    continue
                request_values = {
                    _logical_value_id(item)
                    for item in request_observations.get(request.id, ())
                    if item.response_id is None and _is_state_observation(item)
                }
                response_value_match = any(
                    item.response_id is not None
                    and _value_search_match(item.normalized_value, selected_raw_values)
                    for item in request_observations.get(request.id, ())
                )
                response = response_by_request.get(request.id)
                response_value_match = response_value_match or (
                    response is not None
                    and any(
                        _response_contains_value(response, value, body_texts)
                        for value in selected_raw_values
                    )
                )
                if request_values & selected_values or response_value_match:
                    selected_requests.add(request.id)
                    selected_values.update(request_values)
                    selected_raw_values.update(
                        item.normalized_value
                        for item in request_observations.get(request.id, ())
                        if item.response_id is None and _is_state_observation(item)
                    )
                    changed = True
        scoped = [
            item for item in observations
            if (
                item.request_id in selected_requests
                and (item.request_id == target_request_id or item.sequence <= target.sequence)
            )
        ]
        return tuple(sorted(scoped, key=lambda item: item.observation_id))

    def _version_values(self, observations: tuple[ValueObservation, ...],
                        value_obs: dict[str, list[str]],
                        cancel_event: Any | None = None) -> dict[str, ValueVersion]:
        by_id = {observation.observation_id: observation for observation in observations}
        result: dict[str, ValueVersion] = {}
        for value_id, observation_ids in sorted(value_obs.items()):
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            ordered = sorted((by_id[item] for item in observation_ids),
                             key=lambda item: (item.sequence, item.observation_id))
            current: ValueVersion | None = None
            for observation in ordered:
                if cancel_event is not None and cancel_event.is_set():
                    raise AnalysisCancelled()
                if current is not None and current.raw_value == observation.normalized_value:
                    continue
                if current is not None:
                    result[current.version_id] = ValueVersion(
                        **{**current.__dict__, "valid_until": observation.sequence})
                version_id = stable_id("version", value_id, observation.sequence,
                                       observation.normalized_value)
                current = ValueVersion(
                    version_id=version_id, value_id=value_id,
                    value_digest=SecretDisplayPolicy.digest(observation.normalized_value),
                    display_value=SecretDisplayPolicy().display(observation.normalized_value),
                    raw_value=observation.normalized_value, valid_from=observation.sequence,
                    valid_until=None,
                )
                result[version_id] = current
            if current is not None:
                result[current.version_id] = current
        return result

    def _infer_producers(self, capture: Capture, observations: tuple[ValueObservation, ...],
                         versions: dict[str, ValueVersion],
                         cancel_event: Any | None = None,
                         body_texts: dict[str, str] | None = None
                         ) -> tuple[dict[str, tuple[ProducerHypothesis, ...]], dict[str, tuple[str, ...]]]:
        requests = {request.id: request for request in capture.requests}
        origins = {
            request.id: urlsplit(request.url).netloc.lower()
            for request in capture.requests
        }
        response_by_value: dict[str, list[ValueObservation]] = {}
        all_response_observations = sorted(
            (item for item in observations if item.response_id is not None),
            key=lambda item: (item.sequence, item.observation_id),
        )
        # Prior response observations grouped per host origin; a transformed
        # match may only pair a consumer with a same-origin earlier response.
        # Sources with an unknown request id are bucketed under None, which a
        # real consumer origin can never equal.
        responses_by_origin: dict[str | None, list[ValueObservation]] = {}
        for item in all_response_observations:
            responses_by_origin.setdefault(
                origins.get(item.request_id) if item.request_id is not None else None,
                [],
            ).append(item)
        request_by_value: dict[str, list[ValueObservation]] = {}
        # Response observations indexed by their Bearer-stripped value:
        # _values_match(left, right) is exactly true when the stripped
        # representations are equal, so this index is lossless.
        response_by_stripped: dict[str, list[ValueObservation]] = {}
        for item in observations:
            index = response_by_value if item.response_id is not None else request_by_value
            index.setdefault(_logical_value_id(item), []).append(item)
            if item.response_id is not None:
                response_by_stripped.setdefault(_strip_bearer(item.normalized_value), []).append(item)
        for index in (response_by_value, request_by_value, response_by_stripped):
            for value_id in index:
                index[value_id].sort(key=lambda item: (item.sequence, item.observation_id))
        producers: dict[str, list[ProducerHypothesis]] = {}
        negative: dict[str, list[str]] = {}
        for version_id, version in sorted(versions.items()):
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            consumers = [
                item for item in request_by_value.get(version.value_id, ())
                if _values_match(item.normalized_value, version.raw_value)
                and item.sequence >= version.valid_from
                and (version.valid_until is None or item.sequence < version.valid_until)
            ]
            if not consumers:
                continue
            first_consumer = min(consumers, key=lambda item: item.sequence)
            method: str | None = None
            same_field_candidates = [
                    source for source in response_by_value.get(version.value_id, ())
                    if source.sequence < first_consumer.sequence
                    and _values_match(source.normalized_value, version.raw_value)
                    and _same_origin(source, first_consumer, origins)
            ]
            candidates: list[ValueObservation] | None = None
            if same_field_candidates:
                candidates = same_field_candidates
                method = "EXACT_VALUE"
            if not candidates:
                # Value identity is established by the captured value, not by
                # producer/consumer field names.
                candidates = [
                    source for source in response_by_stripped.get(
                        _strip_bearer(version.raw_value), ()
                    )
                    if source.sequence < first_consumer.sequence
                ]
                if candidates:
                    same_origin_candidates = [
                        source for source in candidates
                        if _same_origin(source, first_consumer, origins)
                    ]
                    if same_origin_candidates:
                        candidates = same_origin_candidates
                        method = "CROSS_FIELD_EXACT_MATCH"
                    else:
                        method = "CROSS_ORIGIN_EXACT_MATCH"
            if not candidates:
                decoded_target = _decode_b64_cached(version.raw_value)
                consumer_origin = (
                    origins.get(first_consumer.request_id)
                    if first_consumer.request_id is not None else None
                )
                prior_same_origin: tuple[ValueObservation, ...] = (
                    tuple(responses_by_origin.get(consumer_origin, ()))
                    if consumer_origin is not None else ()
                )
                # Bucket keeps the globally sorted ascending order, so the
                # first observation at or past the consumer ends the scan.
                transformed: list[ValueObservation] = []
                for source in prior_same_origin:
                    if cancel_event is not None and cancel_event.is_set():
                        raise AnalysisCancelled()
                    if source.sequence >= first_consumer.sequence:
                        break
                    if (
                        _values_match(
                            _unquote_cached(source.normalized_value),
                            _unquote_cached(version.raw_value),
                        )
                        or (decoded_target is not None
                            and source.normalized_value == decoded_target)
                        or _values_match(
                            _decode_b64_cached(source.normalized_value) or "",
                            version.raw_value,
                        )
                    ):
                        transformed.append(source)
                if transformed:
                    candidates = transformed
                    method = "TRANSFORMED_MATCH"
            if not candidates and len(version.raw_value) >= 4:
                candidates = self._raw_text_candidates(
                    capture, requests, first_consumer, version.raw_value, body_texts
                )
                if candidates:
                    method = "RAW_TEXT_MATCH"
            assert candidates is not None
            if not candidates:
                evidence_id = stable_id("evidence", version_id, "NO_PRIOR_RESPONSE_MATCH")
                negative[version_id] = [evidence_id]
                continue
            if method is None:
                raise RuntimeError("Producer candidates were found without a match method")
            hypotheses: list[ProducerHypothesis] = []
            for source in sorted(candidates, key=lambda item: (item.response_id or "", item.observation_id)):
                if cancel_event is not None and cancel_event.is_set():
                    raise AnalysisCancelled()
                evidence_ids = (
                    stable_id("evidence", source.observation_id, version_id, method),
                    stable_id("evidence", source.observation_id, version_id, "TEMPORAL_PRECEDENCE"),
                    stable_id("evidence", source.observation_id, version_id, "FIELD_CORRESPONDENCE"),
                )
                base_score = {
                    "EXACT_VALUE": 0.95,
                    "CROSS_FIELD_EXACT_MATCH": 0.72,
                    "CROSS_ORIGIN_EXACT_MATCH": 0.58,
                    "RAW_TEXT_MATCH": 0.68,
                    "TRANSFORMED_MATCH": 0.62,
                }[method]
                confidence = (
                    aggregate_confidence((base_score, 0.9, 0.8))
                    if method == "EXACT_VALUE" else base_score
                )
                hypotheses.append(ProducerHypothesis(
                    producer=f"response_{source.response_id}",
                    value_version=version_id, evidence_ids=evidence_ids,
                    confidence=confidence, status="SUPPORTED" if confidence >= 0.8 else "CANDIDATE",
                    category=(DependencyCategory.SUPPORTED if method == "EXACT_VALUE" and confidence >= 0.8
                              else DependencyCategory.OBSERVATIONAL),
                ))
            producers[version_id] = hypotheses
        return ({key: tuple(value) for key, value in producers.items()},
                {key: tuple(value) for key, value in negative.items()})

    @staticmethod
    def _raw_text_candidates(
        capture: Capture,
        requests: dict[str, Any],
        consumer: ValueObservation,
        value: str,
        text_cache: dict[str, str] | None = None,
    ) -> list[ValueObservation]:
        candidates: list[ValueObservation] = []
        texts: dict[str, str] = text_cache if text_cache is not None else {}
        for response in capture.responses:
            source_request = requests.get(response.request_id)
            if source_request is None or source_request.sequence >= consumer.sequence:
                continue
            if not _response_contains_value(response, value, texts):
                continue
            candidates.append(ValueObservation(
                observation_id=stable_id(
                    "raw-response-match", response.id, value
                ),
                location=SourceLocation(
                    "response.raw_text", "$raw", response.request_id, response.id
                ),
                raw_value=value,
                normalized_value=value,
                timestamp=source_request.timestamp,
                sequence=source_request.sequence,
                semantic_hints=(),
            ))
        return candidates

    def _add_capture_nodes(self, graph: Graph, capture: Capture,
                           cancel_event: Any | None = None) -> None:
        for request in capture.requests:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            graph.add_node(Node(request.id, NodeType.REQUEST,
                                f"{request.method} {url_path(request.url)}",
                                {"sequence": request.sequence, "url": request.url}))
        for response in capture.responses:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            graph.add_node(Node(response.id, NodeType.RESPONSE, f"HTTP {response.status}",
                                {"request_id": response.request_id, "status": response.status}))

    def _add_edges(self, graph: Graph, capture: Capture,
                   observations: tuple[ValueObservation, ...],
                   versions: dict[str, ValueVersion],
                   producers: dict[str, tuple[ProducerHypothesis, ...]],
                   negative: dict[str, tuple[str, ...]],
                   cancel_event: Any | None = None) -> None:
        for observation in observations:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            if not _is_state_observation(observation):
                continue
            value_id = _logical_value_id(observation)
            edge, evidence = self._edge(observation, value_id, EdgeType.OBSERVED_IN,
                                        "OBSERVATION_LOCATION", 1.0)
            graph.add_evidence(evidence)
            graph.add_edge(edge)
        observations_by_request: dict[str, list[ValueObservation]] = {}
        for observation in observations:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            if observation.request_id:
                observations_by_request.setdefault(observation.request_id, []).append(observation)
        versions_by_value = _index_versions_by_value(versions)
        for request in capture.requests:
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            for observation in observations_by_request.get(request.id, ()):
                if observation.request_id != request.id or observation.response_id is not None:
                    continue
                version = _version_for(versions_by_value, observation, request.sequence)
                if version is not None:
                    edge, evidence = self._edge(request, version.version_id, EdgeType.CONSUMES,
                                                "TEMPORAL_VERSION_MATCH", 1.0)
                    graph.add_evidence(evidence)
                    graph.add_edge(edge)
        for version_id, hypotheses in sorted(producers.items()):
            if cancel_event is not None and cancel_event.is_set():
                raise AnalysisCancelled()
            for hypothesis in hypotheses:
                descriptions = (
                    ("MATCH", "Identical observed value in a prior response."
                     if hypothesis.confidence >= 0.8 else "Value correspondence.", 0.95),
                    ("TEMPORAL_PRECEDENCE", "Source response precedes the first consumer.", 0.9),
                    ("FIELD_CORRESPONDENCE", "Source and consumer have compatible structural field keys.", 0.8),
                )
                for evidence_id, (kind, description, score) in zip(
                    hypothesis.evidence_ids, descriptions, strict=True
                ):
                    if cancel_event is not None and cancel_event.is_set():
                        raise AnalysisCancelled()
                    graph.add_evidence(Evidence(
                        evidence_id, kind, description,
                        (hypothesis.producer.removeprefix("response_"), version_id), score,
                    ))
                graph.add_edge(Edge(
                    stable_id("edge", hypothesis.producer, version_id, EdgeType.PRODUCES.value,
                               evidence.evidence_id),
                    hypothesis.producer, version_id, EdgeType.PRODUCES,
                    hypothesis.evidence_ids, hypothesis.confidence,
                    "RESPONSE_VALUE_MATCH",
                    hypothesis.category,
                ))
        for version_id in sorted(negative):
            for evidence_id in negative[version_id]:
                graph.add_evidence(Evidence(
                    evidence_id, "NO_PRIOR_RESPONSE_MATCH",
                    "No compatible prior response observation matched this consumed value.",
                    (version_id,), 1.0,
                ))

    @staticmethod
    def _edge(observation: Any, target: str, edge_type: EdgeType,
              method: str, confidence: float) -> tuple[Edge, Evidence]:
        source = getattr(observation, "id", None)
        if source is None:
            source = getattr(observation, "response_id", None) or getattr(observation, "request_id", None)
        if source is None:
            raise ValueError("Graph source must have a stable ID")
        source_id = getattr(observation, "observation_id", source)
        evidence_id = stable_id("evidence", source_id, target, edge_type.value)
        evidence = Evidence(evidence_id, "OBSERVATION", "Observed at a captured source location.",
                            (source_id,), confidence)
        return (Edge(stable_id("edge", source, target, edge_type.value, evidence_id),
                     source, target, edge_type, (evidence_id,), confidence, method), evidence)


def _logical_value_id(observation: ValueObservation) -> str:
    path = observation.location.path or ""
    if observation.semantic_hint and observation.semantic_hint.startswith("cookie."):
        structural_key = f"cookie:{observation.semantic_hint.removeprefix('cookie.')}"
    else:
        leaf = path.rsplit(".", 1)[-1].rsplit("/", 1)[-1]
        leaf = leaf.split("[", 1)[0].lower()
        leaf = leaf.removeprefix("x-")
        structural_key = f"field:{_canonical_hint(leaf)}"
    return stable_id("value", structural_key)


def _ignored_observation(observation: ValueObservation, ignored: set[str]) -> bool:
    hints = {hint.lower() for hint in observation.semantic_hints}
    path_leaf = (observation.location.path or "").rsplit(".", 1)[-1].lower()
    expanded_hints = hints | {
        hint.removeprefix("cookie.") for hint in hints if hint.startswith("cookie.")
    }
    return bool(expanded_hints & ignored) or path_leaf in ignored


def _drop_named_values(observations: tuple[ValueObservation, ...],
                       ignored_values: set[str]) -> tuple[ValueObservation, ...]:
    """Remove whole logical values whose name forms match an ignore set.

    One value can surface under different raw names at different locations
    (request-side keys, response headers such as ``X-*``, or canonical
    semantic hints), so observation-level name matching would ignore it at
    some requests and keep it at others. Both the bucket names and the
    ignored names are therefore canonicalized; any single-form match drops
    the value capture-wide, whatever name its observations carry.
    """
    checked = {_canonical_hint(item) for item in ignored_values if item}
    if not checked:
        return observations
    structural_by_observation_id: dict[str, str] = {}
    names_by_structural: dict[str, set[str]] = {}
    for observation in observations:
        structural_id = _logical_value_id(observation)
        structural_by_observation_id[observation.observation_id] = structural_id
        names = names_by_structural.setdefault(structural_id, set())
        names.update(_canonical_hint(hint) for hint in observation.semantic_hints)
        leaf = (observation.location.path or "").rsplit(".", 1)[-1]
        names.add(_canonical_hint(leaf))
    dropped = {
        structural_id for structural_id, names in names_by_structural.items()
        if names & checked
    }
    if not dropped:
        return observations
    return tuple(
        item for item in observations
        if structural_by_observation_id[item.observation_id] not in dropped
    )


def _canonical_hint(hint: str) -> str:
    lowered = hint.lower().strip()
    if lowered.startswith("cookie."):
        lowered = lowered.removeprefix("cookie.")
    lowered = lowered.removeprefix("x-")
    if lowered in {"csrf", "csrf-token", "csrf_token", "xsrf-token", "xsrf_token"}:
        return "csrf"
    if lowered in {"bearer", "bearer-token", "bearer_token", "access-token"}:
        return "access_token"
    return lowered


def _is_state_observation(observation: ValueObservation) -> bool:
    container = observation.location.container
    if container == "request.path":
        return False
    if container == "request.header":
        return _state_hint(observation.semantic_hint)
    if container in {"request.cookie", "request.cookies", "response.set_cookie",
                     "response.cookies"}:
        return True
    return _state_hint(observation.semantic_hint)


def _state_hint(hint: str | None) -> bool:
    if not hint:
        return False
    lowered = hint.lower()
    if lowered.startswith("x-"):
        return True
    return any(term in lowered for term in (
        "token", "csrf", "xsrf", "auth", "session", "cookie", "signature",
        "nonce", "secret", "api-key", "apikey", "key", "captcha", "otp",
    ))


def _index_versions_by_value(versions: dict[str, ValueVersion]) -> dict[str, tuple[ValueVersion, ...]]:
    grouped: dict[str, list[ValueVersion]] = {}
    for version in versions.values():
        grouped.setdefault(version.value_id, []).append(version)
    return {value_id: tuple(items) for value_id, items in grouped.items()}


def _version_for(versions_by_value: dict[str, tuple[ValueVersion, ...]],
                 observation: ValueObservation,
                 sequence: int) -> ValueVersion | None:
    candidates = [
        version for version in versions_by_value.get(_logical_value_id(observation), ())
        if _values_match(version.raw_value, observation.normalized_value)
        and version.valid_from <= sequence
        and (version.valid_until is None or sequence < version.valid_until)
    ]
    return max(candidates, key=lambda version: version.valid_from, default=None)


def _value_label(value_id: str) -> str:
    return value_id.replace("value_", "value:")


def url_path(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).path or "/"


def aggregate_confidence(scores: tuple[float, ...]) -> float:
    """Combine independent evidence with deterministic diminishing returns."""
    remaining = 1.0
    for score in sorted(scores, reverse=True):
        remaining *= 1.0 - max(0.0, min(1.0, score))
    return round(1.0 - remaining, 6)


def _same_origin(source: ValueObservation, target: ValueObservation,
                 origins: dict[str, str]) -> bool:
    """True when source and target requests share the same host:port."""
    source_origin = origins.get(source.request_id or "")
    target_origin = origins.get(target.request_id or "")
    if source_origin is None or target_origin is None:
        return False
    return source_origin == target_origin


def _values_match(left: str, right: str) -> bool:
    """Compare captured values while treating Bearer as transport syntax."""
    if left == right:
        return True
    return _strip_bearer(left) == _strip_bearer(right)


def _value_search_match(value: str, targets: set[str]) -> bool:
    if any(_values_match(value, target) for target in targets):
        return True
    decoded_value = _unquote_cached(value)
    decoded_base64 = _decode_b64_cached(value)
    return any(
        _values_match(decoded_value, target)
        or (decoded_base64 is not None and _values_match(decoded_base64, target))
        for target in targets
    )


def _response_contains_value(response: Any, value: str,
                             text_cache: dict[str, str] | None = None) -> bool:
    """Search the captured response as text, without inspecting its format."""
    if not value:
        return False
    values = {value, _strip_bearer(value)}
    texts = [header.value for header in response.headers]
    texts.extend(cookie.value for cookie in response.cookies)
    if response.body:
        texts.append(_response_text(response, text_cache))
    return any(candidate and candidate in text for candidate in values for text in texts)


def _response_text(response: Any, text_cache: dict[str, str] | None = None) -> str:
    """Decode a response body once and reuse the decoded text across lookups."""
    cache_key = str(getattr(response, "id", ""))
    if text_cache is not None and cache_key and cache_key in text_cache:
        return text_cache[cache_key]
    text = response.body.decode("utf-8", errors="replace")
    if text_cache is not None and cache_key:
        text_cache[cache_key] = text
    return text


@cache
def _strip_bearer(value: str) -> str:
    """Strip a Bearer transport prefix; memoized for repeat comparisons."""
    match = re.match(r"^\s*Bearer\s+(.+?)\s*$", value, flags=re.IGNORECASE)
    return match.group(1) if match else value


_unquote_cached = cache(unquote)
_decode_b64_cached = cache(decode_base64_candidate)
