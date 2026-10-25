from __future__ import annotations

import base64
import json

import pytest

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.capture import HarFormatError, HarProvider
from reqvexa.extraction import extract_observations
from reqvexa.models import EdgeType, Graph, Node, NodeType, SecretDisplayPolicy
from reqvexa.planning import plan_flow, report_markdown, safe_report
from reqvexa.provenance import ProvenanceEngine


def entry(method: str, url: str, *, headers=None, cookies=None, post_data=None,
          response=None, started=None, timings=None):
    return {
        "startedDateTime": started or "2026-08-29T00:00:00Z",
        "time": 1,
        "timings": timings or {"wait": 1},
        "request": {
            "method": method, "url": url, "httpVersion": "HTTP/1.1",
            "headers": headers or [], "cookies": cookies or [],
            **({"postData": post_data} if post_data is not None else {}),
        },
        **({"response": response} if response is not None else {}),
    }


def response(status=200, headers=None, text=None, mime="application/json", cookies=None):
    content = {"size": len(text or ""), "mimeType": mime}
    if text is not None:
        content["text"] = text
    return {"status": status, "headers": headers or [], "cookies": cookies or [],
            "content": content}


def har(entries):
    return {"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}}


def test_har_preserves_order_duplicates_and_missing_response():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/a?x=a%2Bb", headers=[
            {"name": "X-Dup", "value": "1"}, {"name": "X-Dup", "value": "2"},
        ], response=response(headers=[
            {"name": "Set-Cookie", "value": "a=1"}, {"name": "Set-Cookie", "value": "b=2"},
        ], text="")),
        entry("POST", "https://example.test/empty"),
    ]))
    assert capture.requests[0].headers[0].index == 0
    assert [h.value for h in capture.requests[0].headers] == ["1", "2"]
    assert len(capture.responses) == 1
    assert capture.requests[1].response_id is None
    assert capture.requests[0].query == (("x", "a+b"),)
    assert [c.name for c in capture.responses[0].cookies] == []


def test_har_stable_ids():
    document = har([entry("GET", "https://example.test/")])
    first = HarProvider().load_json(document)
    second = HarProvider().load_json(document)
    assert [item.id for item in first.requests] == [item.id for item in second.requests]
    assert [item.source_entry_id for item in first.requests] == [item.source_entry_id for item in second.requests]


def test_body_extraction_json_and_form():
    capture = HarProvider().load_json(har([
        entry("POST", "https://example.test/json", post_data={
            "mimeType": "application/json", "text": '{"nested":{"csrf":"ABC"}}',
        }),
        entry("POST", "https://example.test/form", post_data={
            "mimeType": "application/x-www-form-urlencoded", "text": "a=1&b=two+words",
        }),
    ]))
    observations = extract_observations(capture)
    paths = {observation.location.path for observation in observations}
    assert "$.nested.csrf" in paths
    assert "a" in paths
    assert "b" in paths


def test_xssi_prefixed_json_response_is_searched_for_values():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/captcha",
              response=response(text=")]}'\n[\"uvresp\",\"CAPTCHA-VALUE\"]")),
        entry("POST", "https://example.test/target", post_data={
            "mimeType": "application/json",
            "text": '{"captchaResponse":"CAPTCHA-VALUE"}',
        }),
    ]))
    analysis = ProvenanceEngine().analyze(
        capture, target_request_id=capture.requests[1].id
    )
    assert any(
        hypothesis.producer.startswith("response_")
        for version in analysis.versions.values()
        if version.raw_value == "CAPTCHA-VALUE"
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    )


def test_bearer_headers_match_with_and_without_prefix():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/bootstrap",
              response=response(headers=[{"name": "Authorization", "value": "token-123"}])),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Authorization", "value": "Bearer token-123"}]),
    ]))
    observations = extract_observations(capture)
    request_observations = [
        item for item in observations
        if item.request_id == capture.requests[1].id
        and item.location.path == "authorization"
    ]
    assert {item.normalized_value for item in request_observations} == {"Bearer token-123"}
    analysis = ProvenanceEngine().analyze(capture, target_request_id=capture.requests[1].id)
    assert any(
        hypothesis.status == "SUPPORTED"
        for version in analysis.versions.values()
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    )


def test_cookie_value_in_response_body_url_decoded_and_cross_field():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/bootstrap",
              response=response(text='{"session_value":"abc%2B123"}')),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Cookie", "value": "session=abc+123"}]),
    ]))
    observations = extract_observations(capture)
    body = [item for item in observations if item.location.path == "$.session_value"]
    assert body and body[0].normalized_value == "abc+123"
    analysis = ProvenanceEngine().analyze(capture)
    producers = [
        hypothesis
        for version in analysis.versions.values()
        if version.raw_value == "abc+123"
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    ]
    assert producers
    assert all(item.category.value == "OBSERVATIONAL_DEPENDENCY" for item in producers)
    assert all(item.confidence < 1 for item in producers)


def test_cookie_value_in_response_body_base64():
    encoded = base64.b64encode(b"session-value").decode()
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/bootstrap",
              response=response(text=json.dumps({"session_value": encoded}))),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Cookie", "value": "session=session-value"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    producers = [
        hypothesis
        for version in analysis.versions.values()
        if version.raw_value == "session-value"
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    ]
    assert producers
    assert all(hypothesis.status == "CANDIDATE" for hypothesis in producers)
    assert all(hypothesis.confidence < 0.8 for hypothesis in producers)


def test_json_document_and_scalar_fallback_are_observed():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/bootstrap",
              response=response(text='{"meta":{"token":"TOKEN-1"}}')),
        entry("POST", "https://example.test/target", post_data={
            "mimeType": "application/json",
            "text": '{"meta":{"token":"TOKEN-1"}}',
        }),
    ]))
    observations = extract_observations(capture)
    assert any(item.location.path == "$" and item.semantic_hint == "json_document"
               for item in observations)
    assert any(item.location.path == "$.meta.token" and item.normalized_value == "TOKEN-1"
               for item in observations)


def test_secret_policy_masks_and_digests():
    policy = SecretDisplayPolicy()
    assert policy.display("super-secret") == "supe********"
    assert "super-secret" not in policy.display("super-secret")
    assert len(policy.digest("super-secret")) == 64
    assert SecretDisplayPolicy(unsafe_raw=True).display("x") == "x"


def test_cookie_mutation_and_temporal_consumption():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/start",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=A"}])),
        entry("GET", "https://example.test/one",
              headers=[{"name": "Cookie", "value": "session=A"}]),
        entry("GET", "https://example.test/rotate",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=B"}])),
        entry("GET", "https://example.test/two",
              headers=[{"name": "Cookie", "value": "session=B"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    versions = sorted(
        (version for version in analysis.versions.values()
         if version.raw_value in {"A", "B"}),
        key=lambda version: version.valid_from,
    )
    assert len(versions) == 2
    assert versions[0].raw_value == "A"
    assert versions[1].raw_value == "B"
    consumed = [
        edge for edge in analysis.graph.edges.values()
        if edge.type == EdgeType.CONSUMES
    ]
    assert len(consumed) >= 2


def test_unseen_target_value_is_hypothesis_not_fact():
    capture = HarProvider().load_json(har([
        entry("POST", "https://example.test/target",
              headers=[{"name": "X-Signature", "value": "never-seen"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    traces = analysis.trace(capture.requests[0].id)
    signature = [
        node for node in traces
        if any(
            observation.semantic_hint == "x-signature"
            and observation.observation_id in analysis.value_observation_ids.get(node.value_id, ())
            for observation in analysis.observations
        )
    ]
    assert signature
    assert signature[0].status == "UNKNOWN"
    assert signature[0].note == "No matching value was observed in prior responses."


def test_stale_value_does_not_resolve_to_latest_version():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/start",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=A"}])),
        entry("GET", "https://example.test/old",
              headers=[{"name": "Cookie", "value": "session=A"}]),
        entry("GET", "https://example.test/rotate",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=B"}])),
        entry("GET", "https://example.test/revert",
              headers=[{"name": "Cookie", "value": "session=A"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    trace = analysis.trace(capture.requests[3].id)
    session = [node for node in trace if node.version_id in analysis.versions
               and analysis.versions[node.version_id].raw_value == "A"]
    assert session
    assert analysis.versions[session[0].version_id].valid_from == 3


def test_multiple_producers_are_preserved():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/one",
              response=response(text='{"token":"A"}')),
        entry("GET", "https://example.test/two",
              response=response(text='{"token":"A"}')),
        entry("GET", "https://example.test/target",
              headers=[{"name": "X-Token", "value": "A"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    token_versions = [v for v in analysis.versions.values() if v.raw_value == "A"]
    hypotheses = [
        hypothesis for version in token_versions
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    ]
    assert len(hypotheses) >= 2


def test_semantically_different_fields_are_not_merged():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(text='{"id":"123"}')),
        entry("POST", "https://example.test/target", post_data={
            "mimeType": "application/json", "text": '{"product_id":"123"}',
        }),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    assert not any(edge.type == EdgeType.PRODUCES for edge in analysis.graph.edges.values())


def test_cycle_trace_terminates():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/a",
              response=response(text='{"a":"B"}')),
        entry("GET", "https://example.test/b",
              headers=[{"name": "X-A", "value": "B"}],
              response=response(text='{"b":"A"}')),
        entry("GET", "https://example.test/target",
              headers=[{"name": "X-B", "value": "A"}]),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    assert analysis.trace(capture.requests[2].id)


def test_transformed_match_is_not_full_confidence():
    encoded = base64.b64encode(b"hello").decode()
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(text=json.dumps({"blob": encoded}))),
        entry("GET", "https://example.test/target?value=hello"),
    ]))
    analysis = ProvenanceEngine().analyze(capture)
    assert all(edge.confidence < 1 for edge in analysis.graph.edges.values()
               if edge.type == EdgeType.PRODUCES)


def test_graph_rejects_evidence_free_edges():
    graph = Graph()
    graph.add_node(Node("a", NodeType.REQUEST, "a"))
    try:
        graph.add_edge(__import__("reqvexa").Edge(
            "e", "a", "b", EdgeType.REQUIRES, (), 1.0, "test"))
    except ValueError as error:
        assert "evidence" in str(error).lower()
    else:
        raise AssertionError("Expected evidence validation error")


def test_target_scoped_analysis_reduces_observation_set():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/noise", response=response(text='{"large":"x"}')),
        entry("GET", "https://example.test/source",
              response=response(text='{"token":"A"}')),
        entry("GET", "https://example.test/target",
              headers=[{"name": "X-Token", "value": "A"}]),
    ]))
    full = ProvenanceEngine().analyze(capture)
    scoped = ProvenanceEngine().analyze(capture, target_request_id=capture.requests[2].id)
    assert len(scoped.observations) < len(full.observations)
    assert scoped.trace(capture.requests[2].id)


def test_flow_plan_contains_only_required_producers_and_target():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/noise",
              response=response(text='{"unused":"noise"}')),
        entry("GET", "https://example.test/source",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=A"}])),
        entry("GET", "https://example.test/target?page=1",
              headers=[{"name": "Cookie", "value": "session=A"}]),
    ]))
    target = capture.requests[2]
    analysis = ProvenanceEngine().analyze(capture, target_request_id=target.id)
    plan = plan_flow(analysis, target.id)
    assert [step.sequence for step in plan.steps] == [1, 2]
    assert plan.steps[-1].role == "target"
    assert plan.unresolved_values == ()


def _first_appearance_capture():
    """A -> B -> target chain with a later echo of B before the target."""
    return HarProvider().load_json(har([
        entry("GET", "https://example.test/bootstrap",
              response=response(text='{"token":"A"}')),
        entry("GET", "https://example.test/middle",
              headers=[{"name": "X-Token", "value": "A"}],
              response=response(text='{"session":"B"}')),
        entry("GET", "https://example.test/echo",
              response=response(text='{"session":"B"}')),
        entry("GET", "https://example.test/target",
              headers=[{"name": "X-Session", "value": "B"}]),
    ]))


def test_one_level_analysis_stops_at_first_appearance():
    capture = _first_appearance_capture()
    target = capture.requests[3]
    recursive = ProvenanceEngine().analyze(capture, target_request_id=target.id)
    one_level = ProvenanceEngine().analyze(
        capture, target_request_id=target.id, recursive=False,
    )

    assert [step.sequence for step in plan_flow(recursive, target.id).steps] == [0, 1, 2, 3]
    one_level_plan = plan_flow(one_level, target.id)
    assert [step.sequence for step in one_level_plan.steps] == [1, 3]
    assert one_level_plan.unresolved_values == ()

    full_root = recursive.trace(target.id)[0]
    flat_root = one_level.trace(target.id)[0]
    assert full_root.children
    assert flat_root.children == ()
    assert len(flat_root.producer_ids) == 1  # the echo request is not repeated

    report = safe_report(one_level, target.id)
    assert report["plan"] == one_level_plan.to_dict()
    assert len(report["values"]) == 1
    assert "session" in report["values"][0]["name"]
    assert [item["sequence"] for item in report["values"][0]["producers"]] == [1]
    recursive_report = safe_report(recursive, target.id)
    assert len(recursive_report["values"]) > len(report["values"])


def test_safe_report_masks_values_and_removes_query_string():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=super-secret"}])),
        entry("GET", "https://example.test/target?token=super-secret",
              headers=[{"name": "Cookie", "value": "session=super-secret"}]),
    ]))
    target = capture.requests[1]
    report = safe_report(ProvenanceEngine().analyze(capture, target_request_id=target.id), target.id)
    rendered = json.dumps(report, sort_keys=True)
    assert "super-secret" not in rendered
    assert "?token=" not in rendered
    assert report["target"]["path"] == "/target"
    assert report["values"][0]["value_digest"]


def test_markdown_report_is_safe_and_structured():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=super-secret"}])),
        entry("GET", "https://example.test/target?token=super-secret",
              headers=[{"name": "Cookie", "value": "session=super-secret"}]),
    ]))
    target = capture.requests[1]
    report = safe_report(ProvenanceEngine().analyze(capture, target_request_id=target.id), target.id)
    markdown = report_markdown(report)
    assert "# Reqvexa Safe Report" in markdown
    assert "## Planned Steps" in markdown
    assert "super-secret" not in markdown
    assert "?token=" not in markdown


def test_analysis_can_ignore_named_values():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[
                  {"name": "Set-Cookie", "value": "session=A"},
                  {"name": "Set-Cookie", "value": "tracking=B"},
              ])),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Cookie", "value": "session=A; tracking=B"}]),
    ]))
    target = capture.requests[1]
    analysis = ProvenanceEngine().analyze(
        capture, target_request_id=target.id, ignored_hints={"tracking"}
    )
    assert any(version.raw_value == "A" for version in analysis.versions.values())
    assert not any(version.raw_value == "B" for version in analysis.versions.values())


def test_file_response_filter_removes_static_response_values_from_matching():
    capture = HarProvider().load_json(har([
        entry(
            "GET", "https://example.test/assets/bundle.js",
            response=response(
                text='{"token":"FILE-ONLY-TOKEN"}',
                mime="application/javascript",
            ),
        ),
        entry("GET", "https://example.test/target", headers=[
            {"name": "X-Token", "value": "FILE-ONLY-TOKEN"},
        ]),
    ]))
    target = capture.requests[1]
    engine = ProvenanceEngine()

    baseline = engine.analyze(capture, target_request_id=target.id)
    baseline_observation = next(
        item for item in baseline.observations
        if item.request_id == target.id
        and item.response_id is None
        and item.normalized_value == "FILE-ONLY-TOKEN"
    )
    baseline_version = baseline._version_for_observation(
        baseline_observation, target.sequence,
    )
    assert baseline_version is not None
    assert baseline.target_producers[baseline_version.version_id]

    filtered = engine.analyze(
        capture, target_request_id=target.id, ignore_file_responses=True,
    )
    target_observation = next(
        item for item in filtered.observations
        if item.request_id == target.id
        and item.response_id is None
        and item.normalized_value == "FILE-ONLY-TOKEN"
    )
    version = filtered._version_for_observation(target_observation, target.sequence)
    assert version is not None
    assert version.version_id not in filtered.target_producers
    assert not any(
        item.request_id == capture.requests[0].id and item.response_id is not None
        for item in filtered.observations
    )
    assert filtered.trace(target.id)[0].status == "UNKNOWN"


def test_http2_pseudo_headers_are_not_extracted_as_regular_headers():
    capture = HarProvider().load_json(har([
        entry(
            "GET", "https://example.test/path",
            headers=[
                {"name": ":method", "value": "GET"},
                {"name": ":authority", "value": "example.test"},
                {"name": ":path", "value": "/path"},
                {"name": "X-Session", "value": "session-123"},
            ],
            response=response(
                headers=[{"name": ":status", "value": "200"}],
                text='{"token":"response-token"}',
            ),
        ),
    ]))

    observations = extract_observations(capture)
    pseudo_names = {":method", ":authority", ":path", ":status"}
    assert not any(
        observation.location.path in pseudo_names
        for observation in observations
    )
    assert any(
        observation.location.path == "x-session"
        and observation.normalized_value == "session-123"
        for observation in observations
    )


def _lazy_fixture_document() -> dict:
    """Unicode-heavy flow: two responses, one entry without a response."""
    return har([
        entry("GET", "https://example.test/source?q=Wörterbuch",
              response=response(headers=[
                  {"name": "Set-Cookie", "value": "session=Münze-Value"},
                  {"name": "Content-Type", "value": "application/json"},
              ], text='{"csrf":"t0ken-é"}')),
        entry("POST", "https://example.test/target",
              post_data={"mimeType": "application/json", "text": '{"payload":"ü€"}'},
              headers=[{"name": "Cookie", "value": "session=Münze-Value"}],
              response=response(headers=[{"name": "X-Frame-Options", "value": "deny"}],
                                text="ok")),
        entry("GET", "https://example.test/bare"),
    ])


def _write_lazy_fixture(tmp_path, name="unicode.har") -> object:
    path = tmp_path / name
    path.write_text(json.dumps(_lazy_fixture_document()), encoding="utf-8")
    return path


def test_lazy_capture_metadata_matches_eager_loading(tmp_path):
    eager = HarProvider().load_json(_lazy_fixture_document())
    lazy = HarProvider().load_file(_write_lazy_fixture(tmp_path), lazy=True)

    assert lazy.entry_store is not None
    assert [request.id for request in lazy.requests] == [
        request.id for request in eager.requests]
    assert [request.method for request in lazy.requests] == [
        request.method for request in eager.requests]
    assert [request.url for request in lazy.requests] == [
        request.url for request in eager.requests]
    assert [request.sequence for request in lazy.requests] == [
        request.sequence for request in eager.requests]
    assert [request.response_id for request in lazy.requests] == [
        request.response_id for request in eager.requests]
    assert [value.id for value in lazy.responses] == [
        value.id for value in eager.responses]
    assert [value.status for value in lazy.responses] == [
        value.status for value in eager.responses]
    for request in lazy.requests:
        assert request.headers == ()
        assert request.cookies == ()
        assert request.body is None
    for value in lazy.responses:
        assert value.headers == ()
        assert value.body is None


def test_lazy_capture_views_full_entry_on_demand(tmp_path):
    eager = HarProvider().load_json(_lazy_fixture_document())
    lazy = HarProvider().load_file(_write_lazy_fixture(tmp_path), lazy=True)

    request, value = lazy.view_entry(lazy.requests[1].id)
    assert request == eager.requests[1]
    assert value == eager.responses[1]
    # repeat views return equivalent (cached) content
    assert lazy.view_entry(lazy.requests[1].id) == (request, value)
    # viewing one entry does not materialize the resident proxies
    assert lazy.requests[1].body is None


def test_ignored_value_names_drop_one_value_capture_wide():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[
                  {"name": "X-Li-Fabric", "value": "dfab"},
                  {"name": "Set-Cookie", "value": "session=keepme"},
              ])),
        entry("GET", "https://example.test/target",
              headers=[
                  {"name": "X-Li-Fabric", "value": "dfab"},
                  {"name": "Cookie", "value": "session=keepme"},
              ],
              response=response(headers=[{"name": "X-Li-Fabric", "value": "dfab"}])),
    ]))
    target = capture.requests[1]
    engine = ProvenanceEngine()

    baseline = engine.analyze(capture, target_request_id=target.id)
    assert any(version.raw_value == "dfab" for version in baseline.versions.values())

    analysis = engine.analyze(
        capture, target_request_id=target.id, ignored_value_names={"x-li-fabric"},
    )
    assert not any(version.raw_value == "dfab" for version in analysis.versions.values())
    assert any(version.raw_value == "keepme" for version in analysis.versions.values())


def test_ignored_value_names_match_canonical_aliases():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[
                  {"name": "Set-Cookie", "value": "csrf_token=alias"},
                  {"name": "Set-Cookie", "value": "session=keepme"},
              ])),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Cookie", "value": "csrf_token=alias; session=keepme"}]),
    ]))
    target = capture.requests[1]
    analysis = ProvenanceEngine().analyze(
        capture, target_request_id=target.id, ignored_value_names={"csrf"},
    )
    assert not any(version.raw_value == "alias" for version in analysis.versions.values())
    assert any(version.raw_value == "keepme" for version in analysis.versions.values())


def test_lazy_capture_dematerializes_after_full_load(tmp_path):
    eager = HarProvider().load_json(_lazy_fixture_document())
    lazy = HarProvider().load_file(_write_lazy_fixture(tmp_path), lazy=True)

    assert lazy.entry_store.materialized is False
    lazy.materialize_all()
    assert lazy.entry_store.materialized is True
    assert lazy.requests[1] == eager.requests[1]
    assert lazy.responses[0] == eager.responses[0]

    lazy.dematerialize()
    assert lazy.entry_store.materialized is False
    assert lazy.requests[1].body is None
    request, _ = lazy.view_entry(lazy.requests[0].id)
    assert request == eager.requests[0]


def test_lazy_capture_engine_analysis_matches_eager(tmp_path):
    eager = HarProvider().load_json(_lazy_fixture_document())
    lazy = HarProvider().load_file(_write_lazy_fixture(tmp_path), lazy=True)
    target = eager.requests[1]

    eager_analysis = ProvenanceEngine().analyze(eager, target_request_id=target.id)
    lazy_analysis = ProvenanceEngine().analyze(
        lazy, target_request_id=lazy.requests[1].id
    )

    def version_shapes(analysis):
        return tuple(sorted(
            (version.version_id, version.value_digest, version.valid_from,
             version.valid_until)
            for version in analysis.versions.values()
        ))

    assert len(lazy_analysis.observations) == len(eager_analysis.observations)
    assert version_shapes(lazy_analysis) == version_shapes(eager_analysis)
    assert len(lazy_analysis.logical_values) == len(eager_analysis.logical_values)
    # the engine released the materialized content after finishing
    assert lazy.requests[0].headers == ()


def test_lazy_capture_rejects_invalid_files(tmp_path):
    newer = tmp_path / "newer.har"
    newer.write_text('{"log":{"version":"2.0","entries":[]}}', encoding="utf-8")
    with pytest.raises(HarFormatError, match=r"Only HAR 1\.2 is supported"):
        HarProvider().load_file(newer, lazy=True)

    malformed = tmp_path / "malformed.har"
    malformed.write_text('{"log":{"version":"1.2","entries":{"a":1}}}', encoding="utf-8")
    with pytest.raises(HarFormatError, match=r"log\.entries must be a list"):
        HarProvider().load_file(malformed, lazy=True)

    broken = tmp_path / "broken.har"
    broken.write_text('{"log":{"version":"1.2","entries":[{?}]}}', encoding="utf-8")
    with pytest.raises(HarFormatError, match="is not valid UTF-8 JSON"):
        HarProvider().load_file(broken, lazy=True)

    missing = tmp_path / "missing.har"
    missing.write_text('{"log":{"version":"1.2","entries":[{}]}}', encoding="utf-8")
    with pytest.raises(HarFormatError, match="Entry 0 has no request object"):
        HarProvider().load_file(missing, lazy=True)

    structure = tmp_path / "structure.har"
    structure.write_text('{"log":{"version":"1.2","entries":[1]}}', encoding="utf-8")
    with pytest.raises(HarFormatError, match="invalid entry structure"):
        HarProvider().load_file(structure, lazy=True)

    empty = tmp_path / "empty.har"
    empty.write_text('{"log":{"version":"1.2","entries":[]}}', encoding="utf-8")
    empty_lazy = HarProvider().load_file(empty, lazy=True)
    assert empty_lazy.requests == () and empty_lazy.responses == ()


def test_analysis_cancellation_is_observed_during_extraction():
    capture = HarProvider().load_json(har([
        entry("GET", f"https://example.test/{index}",
              response=response(text='{"token":"value"}'))
        for index in range(4)
    ]))
    import threading
    cancel_event = threading.Event()

    def progress(stage, current, total, message):
        if stage == "extract" and current == 1:
            cancel_event.set()

    try:
        ProvenanceEngine().analyze(capture, progress_callback=progress,
                                   cancel_event=cancel_event)
    except AnalysisCancelled:
        pass
    else:
        raise AssertionError("Expected analysis cancellation")


def test_observation_stream_is_ordered_and_report_uses_value_names():
    capture = HarProvider().load_json(har([
        entry("GET", "https://example.test/source",
              response=response(headers=[{"name": "Set-Cookie", "value": "session=A"}])),
        entry("GET", "https://example.test/target",
              headers=[{"name": "Cookie", "value": "session=A"}]),
    ]))
    streamed = []
    analysis = ProvenanceEngine().analyze(
        capture,
        target_request_id=capture.requests[1].id,
        observation_callback=lambda request_id, sequence, observations:
            streamed.append((sequence, len(observations))),
    )
    assert [sequence for sequence, _ in streamed] == [0, 1]
    report = __import__("reqvexa.planning", fromlist=["safe_report"]).safe_report(
        analysis, capture.requests[1].id
    )
    assert any(item["name"] == "session" for item in report["values"])
