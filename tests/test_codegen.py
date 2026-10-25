from __future__ import annotations

import ast
import asyncio
import base64
import re
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from reqvexa.capture.har import HarProvider
from reqvexa.codegen import generate_python
from reqvexa.models import Cookie, Header, HttpRequest
from reqvexa.provenance import ProvenanceEngine


def request(
    sequence: int,
    *,
    method: str = "GET",
    url: str = "https://example.test/path",
    headers: tuple[Header, ...] = (),
    cookies: tuple[Cookie, ...] = (),
    body: bytes | None = None,
    raw: dict | None = None,
) -> HttpRequest:
    return HttpRequest(
        id=f"request-{sequence}",
        sequence=sequence,
        timestamp=None,
        method=method,
        url=url,
        query=(),
        headers=headers,
        cookies=cookies,
        body=body,
        body_encoding=None,
        initiator=None,
        response_id=None,
        source_entry_id=f"entry-{sequence}",
        raw=raw or {},
    )


def _har_entry(
    method: str,
    url: str,
    *,
    headers: list[dict[str, str]] | None = None,
    cookies: list[dict[str, object]] | None = None,
    response_headers: list[dict[str, str]] | None = None,
    response_text: str = "{}",
) -> dict:
    return {
        "startedDateTime": "2026-10-25T00:00:00Z",
        "time": 1,
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": headers or [],
            "cookies": cookies or [],
        },
        "response": {
            "status": 200,
            "httpVersion": "HTTP/1.1",
            "headers": response_headers or [],
            "cookies": [],
            "content": {"mimeType": "application/json", "text": response_text},
        },
    }


def _analyze_entries(entries: list[dict]):
    capture = HarProvider().load_json({"log": {"version": "1.2", "entries": entries}})
    analysis = ProvenanceEngine().analyze(
        capture,
        target_request_id=capture.requests[-1].id,
    )
    return capture, analysis


def _run_generated_sync(
    monkeypatch,
    code: str,
    response_headers: list[dict[str, str]],
    namespace_values: dict[str, str] | None = None,
):
    calls: list[dict] = []
    responses = [
        SimpleNamespace(status_code=200, headers=headers)
        for headers in response_headers
    ]

    class FakeSession:
        def __init__(self):
            self.force_http1 = False
            self.cookies: dict[str, str] = {}
            self.headers: dict[str, str] = {"User-Agent": "default"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute_request(self, *, method, url, **kwargs):
            headers = dict(kwargs.get("headers", {}))
            if self.cookies:
                jar_header = "; ".join(
                    f"{name}={value}" for name, value in self.cookies.items()
                )
                explicit_cookie = headers.get("Cookie")
                headers["Cookie"] = (
                    f"{explicit_cookie}; {jar_header}" if explicit_cookie
                    else jar_header
                )
            calls.append({
                "method": method,
                "url": url,
                "headers": headers,
                "data": kwargs.get("data"),
                "json": kwargs.get("json"),
            })
            response = responses.pop(0)
            for name, value in response.headers.items():
                if name.casefold() == "set-cookie":
                    cookie_name, _, cookie_value = value.partition("=")
                    self.cookies[cookie_name] = cookie_value.split(";", 1)[0]
            return response

    monkeypatch.setitem(
        sys.modules,
        "tls_client",
        SimpleNamespace(Session=FakeSession),
    )
    namespace = {"__name__": "generated_test"}
    exec(compile(code, "<generated-flow>", "exec"), namespace)
    namespace.update(namespace_values or {})
    namespace["run"]()
    return calls, namespace


def test_generation_reconstructs_pseudo_headers_and_separates_cookies():
    captured = request(
        4,
        url="",
        method="",
        headers=(
            Header(":method", "POST", 0),
            Header(":scheme", "https", 1),
            Header(":authority", "api.example.test", 2),
            Header(":path", "/v1/items?page=2", 3),
            Header("Host", "ignored.example.test", 4),
            Header("Content-Length", "999", 5),
            Header("Cookie", "sid=header-value==; theme=dark", 6),
            Header("X-Trace", "first", 7),
            Header("x-trace", "second", 8),
            Header("Content-Type", "application/json", 9),
            Header("Transfer-Encoding", "chunked", 10),
        ),
        cookies=(Cookie("sid", "har-value=="),),
        body=b'{"name":"widget"}',
        raw={"httpVersion": "HTTP/2"},
    )

    code = generate_python([captured])
    request_block = code.split("REQUESTS = ", 1)[1].split("\n\n", 1)[0]
    config = ast.literal_eval(request_block)
    config = config[0]

    assert config["method"] == "POST"
    assert config["url"] == "https://api.example.test/v1/items?page=2"
    assert config["headers"] == {
        "X-Trace": "first, second",
        "Content-Type": "application/json",
    }
    assert config["header_order"] == ["cookie", "X-Trace", "Content-Type"]
    assert config["cookies"] == {"sid": "har-value==", "theme": "dark"}
    assert config["json"] == {"name": "widget"}
    assert "force_http1" in config and config["force_http1"] is False
    assert ":method" not in code
    assert "ignored.example.test" not in code
    assert "999" not in code


def test_cookie_order_is_kept_for_structured_har_cookies():
    captured = request(
        1,
        headers=(
            Header("X-First", "one", 0),
            Header("Accept", "*/*", 1),
        ),
        cookies=(Cookie("session", "captured-value"),),
        raw={"httpVersion": "HTTP/1.1"},
    )
    config = ast.literal_eval(
        generate_python([captured])
        .split("REQUESTS = ", 1)[1]
        .split("\n\n", 1)[0]
    )[0]

    assert config["cookies"] == {"session": "captured-value"}
    assert config["header_order"] == ["X-First", "Accept", "Cookie"]


def test_generation_preserves_raw_payload_and_uses_json_for_json_objects():
    json_request = request(
        1,
        method="POST",
        headers=(Header("Content-Type", "application/problem+json; charset=utf-8", 0),),
        body=b'{"items":[1,2]}',
        raw={"httpVersion": "HTTP/1.1"},
    )
    raw_request = request(
        2,
        method="POST",
        headers=(Header("Content-Type", "application/x-www-form-urlencoded", 0),),
        body=b"payload=a%2Fb&empty=",
        raw={"httpVersion": "HTTP/2"},
    )

    code = generate_python([json_request, raw_request])
    configs = ast.literal_eval(code.split("REQUESTS = ", 1)[1].split("\n\n", 1)[0])

    assert configs[0]["json"] == {"items": [1, 2]}
    assert configs[0]["force_http1"] is True
    assert configs[1]["data"] == b"payload=a%2Fb&empty="
    assert configs[1]["force_http1"] is False


def test_generation_uses_host_and_har_mime_fallbacks_and_preserves_json_scalars():
    form_request = request(
        1,
        method="POST",
        url="/submit?source=har",
        headers=(Header("Host", "example.test", 0),),
        body=b"not-json",
        raw={
            "httpVersion": "HTTP/1.1",
            "postData": {"mimeType": "application/x-www-form-urlencoded"},
        },
    )
    scalar_json = request(
        2,
        method="POST",
        headers=(Header("Content-Type", "application/json", 0),),
        body=b'"keep this exact"',
    )

    configs = ast.literal_eval(
        generate_python([form_request, scalar_json])
        .split("REQUESTS = ", 1)[1]
        .split("\n\n", 1)[0]
    )
    assert configs[0]["url"] == "https://example.test/submit?source=har"
    assert configs[0]["headers"] == {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    assert configs[0]["data"] == b"not-json"
    assert configs[1]["data"] == b'"keep this exact"'
    assert "json" not in configs[1]

    with pytest.raises(ValueError, match="no absolute URL or :authority"):
        generate_python([request(3, url="", headers=(Header(":method", "GET", 0),))])


def test_generated_sync_and_async_flows_are_valid_python():
    captured = request(1)
    sync_code = generate_python([captured])
    async_code = generate_python([captured], asynchronous=True)

    ast.parse(sync_code)
    ast.parse(async_code)
    assert "with tls_client.Session() as session:" in sync_code
    assert "async with tls_client.AsyncSession() as session:" in async_code
    assert "await" not in sync_code
    assert "await session.execute_request(" in async_code
    assert "session.session.force_http1" in async_code
    assert "allow_redirects" in sync_code


def test_single_request_generation_emits_one_independent_request():
    captured = request(
        3,
        method="POST",
        url="https://example.test/submit?mode=fast",
        headers=(
            Header("Content-Type", "application/json", 0),
            Header("Cookie", "session=one", 1),
            Header("Content-Length", "17", 2),
            Header("X-Trace", "trace-value", 3),
        ),
        body=b'{"name":"widget"}',
        raw={"httpVersion": "HTTP/1.1"},
    )

    code = generate_python([captured], single_request=True)
    tree = ast.parse(code)
    assigned_literals = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"url", "cookies", "headers", "post_data"}
    }

    assert assigned_literals["url"] == "https://example.test/submit?mode=fast"
    assert assigned_literals["headers"] == {
        "Content-Type": "application/json",
        "Cookie": "session=one",
        "Content-Length": "17",
        "X-Trace": "trace-value",
    }
    assert assigned_literals["cookies"] == {"session": "one"}
    assert assigned_literals["post_data"] == '{"name":"widget"}'
    assert "session.header_order = list(headers.keys())" in code
    assert "header_name.casefold()" in code
    assert "session.force_http1 = True" in code
    assert "session.post(url, headers=headers, cookies=cookies, data=post_data)" in code
    assert "REQUESTS" not in code
    assert "session.execute_request(" not in code


def test_single_request_generation_requires_exactly_one_request():
    with pytest.raises(ValueError, match="exactly one request"):
        generate_python([request(1), request(2)], single_request=True)


def test_single_request_generation_preserves_raw_edge_case_fields():
    captured = request(
        6,
        method="",
        url="",
        headers=(
            Header(":method", "PROPFIND", 0),
            Header(":scheme", "https", 1),
            Header(":authority", "api.example.test", 2),
            Header(":path", "/resource?q=one", 3),
            Header("Host", "ignored.example.test", 4),
            Header("Content-Length", "2", 5),
            Header("x-repeat", "one", 6),
            Header("X-Repeat", "two", 7),
        ),
        cookies=(Cookie("sid", "cookie-value"),),
        body=b"\xff\x00",
        raw={
            "httpVersion": "HTTP/2",
            "postData": {"mimeType": "application/octet-stream"},
        },
    )

    code = generate_python([captured], single_request=True)
    tree = ast.parse(code)
    assigned_literals = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"url", "cookies", "headers", "post_data"}
    }

    assert assigned_literals["url"] == "https://api.example.test/resource?q=one"
    assert assigned_literals["cookies"] == {"sid": "cookie-value"}
    assert assigned_literals["headers"] == {
        "Host": "ignored.example.test",
        "Content-Length": "2",
        "x-repeat": "one, two",
        "cookie": "sid=cookie-value",
        "Content-Type": "application/octet-stream",
    }
    assert assigned_literals["post_data"] == b"\xff\x00"
    assert "session.execute_request(method='PROPFIND'" in code
    assert "session.force_http1 = False" in code


def test_single_request_generation_requires_http_method():
    with pytest.raises(ValueError, match="no HTTP method"):
        generate_python(
            [request(7, method="", url="")],
            single_request=True,
        )


def test_single_request_merges_cookie_headers_and_ignores_blank_header_names():
    captured = request(
        10,
        headers=(
            Header("", "ignored", 0),
            Header("Cookie", "first=one", 1),
            Header("cookie", "second=two", 2),
        ),
    )

    code = generate_python([captured], single_request=True)
    tree = ast.parse(code)
    assigned_literals = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"cookies", "headers"}
    }

    assert assigned_literals["headers"] == {"Cookie": "first=one; second=two"}
    assert assigned_literals["cookies"] == {"first": "one", "second": "two"}


def test_single_request_url_uses_host_fallback_and_requires_authority():
    captured = request(
        8,
        url="/resource?source=har",
        headers=(Header("Host", "example.test", 0),),
    )

    code = generate_python([captured], single_request=True)
    assert "url = 'https://example.test/resource?source=har'" in code
    assert "response = session.get(url, headers=headers, cookies=cookies)" in code

    with pytest.raises(ValueError, match="no absolute URL or :authority"):
        generate_python(
            [request(9, url="", method="GET")],
            single_request=True,
        )


def test_single_request_sync_and_async_code_execute_once(monkeypatch):
    captured = request(
        5,
        method="POST",
        url="https://example.test/once",
        headers=(
            Header(":method", "POST", 0),
            Header(":authority", "example.test", 1),
            Header(":path", "/once", 2),
            Header("host", "example.test", 3),
            Header("content-length", "7", 4),
            Header("cookie", "session=captured", 5),
            Header("X-Trace", "trace-value", 6),
        ),
        cookies=(Cookie("session", "captured"),),
        body=b"payload",
        raw={"httpVersion": "HTTP/2"},
    )
    calls: list[tuple[str, dict, bool, list[str]]] = []
    response = SimpleNamespace(status_code=201)

    class FakeSession:
        def __init__(self):
            self.force_http1 = True
            self.headers = {"User-Agent": "default"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            calls.append((
                url, kwargs, self.force_http1, self.header_order,
            ))
            return response

    class FakeAsyncSession:
        def __init__(self):
            self.session = FakeSession()
            self.headers = self.session.headers

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, **kwargs):
            return self.session.post(url, **kwargs)

    monkeypatch.setitem(
        sys.modules,
        "tls_client",
        SimpleNamespace(Session=FakeSession, AsyncSession=FakeAsyncSession),
    )

    sync_namespace = {"__name__": "generated_sync"}
    sync_code = generate_python([captured], single_request=True)
    exec(compile(sync_code, "<generated-single-sync>", "exec"), sync_namespace)
    assert sync_namespace["response"] is response

    assert len(calls) == 1
    assert calls[0][0] == "https://example.test/once"
    assert calls[0][1]["headers"] == {"X-Trace": "trace-value"}
    assert calls[0][1]["cookies"] == {"session": "captured"}
    assert calls[0][1]["data"] == "payload"
    assert calls[0][2] is False
    assert calls[0][3] == [
        "host", "content-length", "cookie", "X-Trace",
    ]

    calls.clear()
    async_namespace = {"__name__": "generated_async"}
    async_code = generate_python(
        [captured], asynchronous=True, single_request=True,
    )
    exec(compile(async_code, "<generated-single-async>", "exec"), async_namespace)
    assert asyncio.run(async_namespace["run"]()) is response
    assert len(calls) == 1
    assert calls[0][0] == "https://example.test/once"
    assert calls[0][2] is False
    assert calls[0][3] == [
        "host", "content-length", "cookie", "X-Trace",
    ]


def test_generated_flows_execute_requests_in_order_without_network(monkeypatch):
    calls: list[tuple[str, str, bool]] = []

    class FakeSession:
        def __init__(self):
            self.force_http1 = False
            self.cookies: dict[str, str] = {}
            self.headers: dict[str, str] = {"User-Agent": "default"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute_request(self, *, method, url, **_kwargs):
            calls.append((method, url, self.force_http1))
            return SimpleNamespace(status_code=204)

    class FakeAsyncSession:
        def __init__(self):
            self.session = FakeSession()
            self.cookies = self.session.cookies
            self.headers = self.session.headers

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def execute_request(self, *, method, url, **kwargs):
            return self.session.execute_request(
                method=method, url=url, **kwargs,
            )

    fake_tls_client = SimpleNamespace(
        Session=FakeSession,
        AsyncSession=FakeAsyncSession,
    )
    monkeypatch.setitem(sys.modules, "tls_client", fake_tls_client)
    requests = [
        request(
            1,
            url="https://example.test/start",
            raw={"httpVersion": "HTTP/1.1"},
        ),
        request(
            2,
            url="https://example.test/finish",
            raw={"httpVersion": "HTTP/2"},
        ),
    ]

    sync_namespace = {"__name__": "__main__"}
    exec(compile(generate_python(requests), "<generated-sync>", "exec"), sync_namespace)
    assert calls == [
        ("GET", "https://example.test/start", True),
        ("GET", "https://example.test/finish", False),
    ]

    calls.clear()
    async_namespace = {"__name__": "__main__"}
    exec(
        compile(generate_python(requests, asynchronous=True), "<generated-async>", "exec"),
        async_namespace,
    )
    assert calls == [
        ("GET", "https://example.test/start", True),
        ("GET", "https://example.test/finish", False),
    ]


def test_generation_requires_at_least_one_request():
    try:
        generate_python([])
    except ValueError as error:
        assert "at least one request" in str(error)
    else:
        raise AssertionError("empty selection should be rejected")


def test_flow_generation_requires_an_http_method():
    with pytest.raises(ValueError, match="no HTTP method"):
        generate_python([request(11, method="")])


def test_malformed_json_request_body_is_preserved_as_raw_bytes():
    captured = request(
        12,
        method="POST",
        headers=(Header("Content-Type", "application/json", 0),),
        body=b"\xffnot-json",
    )

    code = generate_python([captured])
    configs = ast.literal_eval(
        code.split("REQUESTS = ", 1)[1].split("\n\n", 1)[0]
    )

    assert configs[0]["data"] == b"\xffnot-json"
    assert "json" not in configs[0]


def test_response_cookies_flow_through_the_session_jar(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/login",
            response_headers=[
                {"name": "Set-Cookie", "value": "session=captured; Path=/; HttpOnly"},
            ],
        ),
        _har_entry(
            "GET",
            "https://example.test/account",
            headers=[{"name": "Cookie", "value": "session=captured"}],
            cookies=[{
                "name": "session",
                "value": "captured",
                "domain": "example.test",
                "path": "/",
                "hostOnly": True,
            }],
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    configs = ast.literal_eval(code.split("REQUESTS = ", 1)[1].split("\n\n", 1)[0])
    assert configs[1]["cookies"] == {}
    assert "session.cookies.clear()" not in code

    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [
            {"Set-Cookie": "session=runtime-value; Path=/"},
            {},
        ],
    )
    assert calls[1]["headers"]["Cookie"] == "session=runtime-value"


def test_domain_cookie_flows_to_a_subdomain_without_manual_extraction():
    entries = [
        _har_entry(
            "GET",
            "https://www.example.test/login",
            response_headers=[{
                "name": "Set-Cookie",
                "value": "session=captured; Domain=example.test; Path=/",
            }],
        ),
        _har_entry(
            "GET",
            "https://api.example.test/account",
            headers=[{"name": "Cookie", "value": "session=captured"}],
            cookies=[{
                "name": "session",
                "value": "captured",
                "domain": ".example.test",
                "path": "/",
                "hostOnly": False,
            }],
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    configs = ast.literal_eval(code.split("REQUESTS = ", 1)[1].split("\n\n", 1)[0])
    assert configs[1]["cookies"] == {}
    assert "MANUAL_BINDINGS = {}" in code


def test_response_header_values_are_read_and_passed_to_later_requests(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/token",
            response_headers=[{"name": "X-Csrf-Token", "value": "captured-token"}],
        ),
        _har_entry(
            "POST",
            "https://example.test/submit",
            headers=[{"name": "X-Csrf-Token", "value": "captured-token"}],
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    assert "HEADER_BINDINGS = {0:" in code
    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [
            {"x-csrf-token": "runtime-token"},
            {},
        ],
    )

    assert calls[1]["headers"]["X-Csrf-Token"] == "runtime-token"


def test_body_value_is_a_manual_variable_and_is_encoded_for_query(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/bootstrap",
            response_text='{"csrf":"captured-body-value"}',
        ),
        _har_entry(
            "GET",
            "https://example.test/submit?csrf=captured-body-value",
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    assert "Manually parse the required value from the body" in code
    standalone_code = generate_python(
        [capture.requests[-1]],
        analysis=analysis,
        single_request=True,
    )
    assert "REPLACE_ME" not in standalone_code
    assert "csrf=captured-body-value" in standalone_code
    variable = re.search(r"^(manual_response_value_\d+) =", code, re.MULTILINE)
    assert variable is not None
    with pytest.raises(RuntimeError, match="manually parsing"):
        _run_generated_sync(monkeypatch, code, [{}, {}])
    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [{}, {}],
        {variable.group(1): "manual/value"},
    )
    assert calls[1]["url"] == "https://example.test/submit?csrf=manual%2Fvalue"


def test_encoded_response_header_is_decoded_then_encoded_for_original_query(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/token",
            response_headers=[{
                "name": "X-Token",
                "value": "old%252Fvalue",
            }],
        ),
        _har_entry(
            "GET",
            "https://example.test/submit?token=old%2Fvalue",
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    assert "url_decode" in code
    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [
            {"x-token": "new%252Fvalue"},
            {},
        ],
    )
    query = urlsplit(calls[1]["url"]).query
    assert query == "token=new%2Fvalue"


def test_base64_response_header_is_decoded_for_later_request(monkeypatch):
    captured = base64.b64encode(b"old/value").decode("ascii")
    runtime = base64.b64encode(b"new/value").decode("ascii")
    entries = [
        _har_entry(
            "GET",
            "https://example.test/token",
            response_headers=[{"name": "X-Token", "value": captured}],
        ),
        _har_entry(
            "GET",
            "https://example.test/submit?token=old%2Fvalue",
        ),
    ]
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    assert "base64_decode" in code
    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [{"x-token": runtime}, {}],
    )
    assert urlsplit(calls[1]["url"]).query == "token=new%2Fvalue"


def test_body_placeholder_is_inserted_into_form_payload(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/bootstrap",
            response_text='{"csrf":"captured value"}',
        ),
        _har_entry(
            "POST",
            "https://example.test/submit",
            headers=[{
                "name": "Content-Type",
                "value": "application/x-www-form-urlencoded",
            }],
        ),
    ]
    entries[1]["request"]["postData"] = {
        "mimeType": "application/x-www-form-urlencoded",
        "text": "csrf=captured+value",
    }
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    variable = re.search(r"^(manual_response_value_\d+) =", code, re.MULTILINE)
    assert variable is not None
    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [{}, {}],
        {variable.group(1): "new/value test"},
    )
    assert calls[1]["data"] == b"csrf=new%2Fvalue+test"


def test_body_value_is_a_manual_variable_in_nested_json_payload(monkeypatch):
    entries = [
        _har_entry(
            "GET",
            "https://example.test/bootstrap",
            response_text='{"auth":{"csrf":"captured-json-value"}}',
        ),
        _har_entry(
            "POST",
            "https://example.test/submit",
            headers=[{"name": "Content-Type", "value": "application/json"}],
        ),
    ]
    entries[1]["request"]["postData"] = {
        "mimeType": "application/json",
        "text": '{"data":{"csrf":"captured-json-value"}}',
    }
    capture, analysis = _analyze_entries(entries)

    code = generate_python(capture.requests, analysis=analysis)
    variable = re.search(r"^(manual_response_value_\d+) =", code, re.MULTILINE)
    assert variable is not None

    calls, _ = _run_generated_sync(
        monkeypatch,
        code,
        [{}, {}],
        {variable.group(1): "runtime-json-value"},
    )

    assert calls[1]["json"] == {"data": {"csrf": "runtime-json-value"}}
