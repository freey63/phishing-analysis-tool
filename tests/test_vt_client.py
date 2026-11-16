import base64

import pytest

from core import vt_client
from core.models import IOC, ReputationVerdict
from core.vt_client import VTClient, VTAuthError, url_to_vt_id


class FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        return self.responses.pop(0)


def _payload(stats, results=None):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": stats,
                "last_analysis_results": results or {},
            }
        }
    }


def test_url_id_is_unpadded_base64():
    expected = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
    assert url_to_vt_id("https://example.com") == expected


def test_malicious_verdict_and_detections(tmp_path):
    session = FakeSession(
        [
            FakeResponse(
                200,
                _payload(
                    {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 4},
                    {"EngineA": {"category": "malicious", "result": "phishing"}},
                ),
            )
        ]
    )
    client = VTClient("secret-key", cache_dir=tmp_path, session=session)
    reputation = client.lookup("domain", "evil.example")

    assert reputation.verdict == ReputationVerdict.MALICIOUS
    assert reputation.total_engines == 68
    assert reputation.detections == ["EngineA: phishing"]
    # The key is only ever placed in the request header.
    assert session.calls[0][1]["x-apikey"] == "secret-key"


def test_clean_result_is_not_called_safe(tmp_path):
    session = FakeSession(
        [FakeResponse(200, _payload({"harmless": 50, "undetected": 10}))]
    )
    client = VTClient("secret-key", cache_dir=tmp_path, session=session)
    reputation = client.lookup("domain", "example.com")

    assert reputation.verdict == ReputationVerdict.CLEAN
    assert "not proof of safety" in reputation.note


def test_404_is_unknown_not_clean(tmp_path):
    client = VTClient("secret-key", cache_dir=tmp_path, session=FakeSession([FakeResponse(404)]))
    reputation = client.lookup("domain", "never-seen.example")
    assert reputation.verdict == ReputationVerdict.UNKNOWN
    assert "Not found" in reputation.note


def test_cache_prevents_duplicate_requests(tmp_path):
    session = FakeSession([FakeResponse(200, _payload({"harmless": 50}))])
    client = VTClient("secret-key", cache_dir=tmp_path, session=session)

    first = client.lookup("domain", "example.com")
    second = client.lookup("domain", "example.com")

    assert len(session.calls) == 1
    assert first.verdict == second.verdict == ReputationVerdict.CLEAN


def test_rate_limit_is_retried_once(tmp_path, monkeypatch):
    monkeypatch.setattr(vt_client.time, "sleep", lambda *_: None)
    session = FakeSession(
        [
            FakeResponse(429, headers={"Retry-After": "0"}),
            FakeResponse(200, _payload({"harmless": 10})),
        ]
    )
    client = VTClient("secret-key", cache_dir=tmp_path, session=session)
    reputation = client.lookup("domain", "example.com")

    assert reputation.verdict == ReputationVerdict.CLEAN
    assert len(session.calls) == 2


def test_auth_error_is_clear(tmp_path):
    client = VTClient("bad-key", cache_dir=tmp_path, session=FakeSession([FakeResponse(401)]))
    with pytest.raises(VTAuthError):
        client.lookup("domain", "example.com")


def test_private_ips_are_not_sent(tmp_path):
    session = FakeSession([])
    client = VTClient("secret-key", cache_dir=tmp_path, session=session)
    reputations = client.lookup_many([IOC(kind="ip", value="192.168.1.5")])

    assert reputations[0].verdict == ReputationVerdict.UNKNOWN
    assert "Private" in reputations[0].note
    assert session.calls == []
