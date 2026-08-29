from __future__ import annotations

import base64
import json

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.capture import HarProvider
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


def test_gui_json_spans_preserve_text_and_color_syntax():
    from reqvexa.gui import _json_spans

    text = '{"key":[true,42,null,"value"]}'
    spans = _json_spans(text)
    assert "".join(span.text or "" for span in spans) == text
    colors = {span.style.color for span in spans if span.style is not None}
    assert {"#A78BFA", "#67E8F9", "#F59E0B", "#FBBF24"} <= colors


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


def test_default_ignored_hints_are_transport_metadata_only():
    from reqvexa.gui import DEFAULT_IGNORED_HINTS

    assert "user-agent" in DEFAULT_IGNORED_HINTS
    assert "sec-fetch-site" in DEFAULT_IGNORED_HINTS
    assert "authorization" not in DEFAULT_IGNORED_HINTS
    assert "cookie" not in DEFAULT_IGNORED_HINTS
