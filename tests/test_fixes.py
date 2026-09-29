#!/usr/bin/env python3
"""Локальные тесты исправлений recon_tool (без сети и без целей)."""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import recon_tool as rt


class FakeResponse:
    def __init__(self, status_code=200, headers=None, body=None):
        self.status_code = status_code
        self.headers = headers or {}
        if body is not None:
            self._json = body

    def json(self):
        return self._json


def test_version_parser_letters():
    vp = rt.VersionParser
    assert vp.compare("1.0.1f", "1.0.1") == 1
    assert vp.compare("1.0.1f", "1.0.1g") == -1
    assert vp.compare("1.0.1", "1.0.2") == -1
    assert vp.compare("1.0.1f", "1.0.2") == -1
    assert vp.compare("8.2p1", "8.2") == 1
    assert vp.compare("2.4.49", "2.4.49") == 0
    # Дистро-суффикс — более поздний патч, чем базовая версия
    assert vp.compare("2.4.41-4ubuntu", "2.4.41") == 1
    assert vp.in_range("2.4.41-4ubuntu", None, "2.4.50") is True
    assert vp.in_range("2.4.49", "2.4.49", "2.4.50")
    assert vp.in_range("2.4.51", "2.4.49", "2.4.50") is False


def test_parse_banner():
    p, v, c = rt.parse_banner("SSH-2.0-OpenSSH_8.2p1 Debian", 22)
    assert p == "OpenSSH" and v == "8.2p1"
    p, v, c = rt.parse_banner("220 ProFTPD Server (Debian)", 21)
    assert p == "ProFTPD"
    p, v, c = rt.parse_banner("220 ProFTPD 1.3.5e Server (Debian)", 21)
    assert p == "ProFTPD" and v == "1.3.5e"


def test_github_circuit_breaker():
    finder = rt.GitHubPoCFinder()
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(params["q"])
        return FakeResponse(403, {"X-RateLimit-Remaining": "0"})

    finder.session = types.SimpleNamespace(get=fake_get)
    assert finder.find_poc("CVE-2021-44228") == []
    # Вызовы прекратились после первого rate limit
    assert len(calls) == 1
    # Повторные вызовы вообще не ходят в сеть
    assert finder.find_poc("CVE-2022-22965") == []
    assert len(calls) == 1


def test_epss_bulk_single_request():
    client = rt.EPSSKEVClient()
    requests_made = []

    def fake_get(url, params=None, timeout=None):
        requests_made.append(params["cve"])
        data = [{"cve": c, "epss": "0.5"} for c in params["cve"].split(",")]
        return FakeResponse(200, body={"data": data})

    client.session = types.SimpleNamespace(get=fake_get)
    cves = [f"CVE-2021-{i}" for i in range(10)]
    client.get_epss_bulk(cves)
    assert len(requests_made) == 1  # один bulk-запрос вместо 10
    assert client.get_epss("CVE-2021-1") == 0.5  # из кэша, без сети


def test_kev_urls_current():
    client = rt.EPSSKEVClient()
    # Изолируемся от реального дискового кэша
    client._kev_cache_file = "/tmp/recon_test_kev_cache.json"
    if os.path.exists(client._kev_cache_file):
        os.remove(client._kev_cache_file)
    fetched = []

    def fake_get(url, timeout=None):
        fetched.append(url)
        if "www.cisa.gov/sites/default/files/feeds" in url:
            return FakeResponse(200, body={"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
        return FakeResponse(404)

    client.session = types.SimpleNamespace(get=fake_get)
    assert client.is_kev("CVE-2021-44228") is True
    assert fetched[0].startswith("https://www.cisa.gov/")


def test_confidence_engine_version_mismatch_penalized():
    class FakeVulners:
        def normalize_cpe(self, cpe):
            return ("apache", "httpd", "2.4.49")

    class FakeEpss:
        def get_priority_score(self, cve):
            return 0.9, True, 1.4

    engine = rt.ConfidenceEngine(FakeVulners(), FakeEpss())
    in_range = engine.score(
        {"product": "Apache httpd", "version": "2.4.49", "banner": "", "cpe": "cpe:2.3:a:apache:httpd:2.4.49"},
        "CVE-2021-41773", "vulners")
    out_of_range = engine.score(
        {"product": "Apache httpd", "version": "2.4.41", "banner": "", "cpe": ""},
        "CVE-2021-41773", "generic")
    assert in_range["score"] > out_of_range["score"]
    assert "Version outside vulnerable range" in out_of_range["reason"]


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"[+] {name}")
            except AssertionError as e:
                failures += 1
                print(f"[-] {name}: {e}")
    sys.exit(1 if failures else 0)
