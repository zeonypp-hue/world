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


def test_nvd_ranges_client_parse_and_cache():
    client = rt.NVDRangesClient()
    client.cache_file = "/tmp/recon_test_nvd.json"
    if os.path.exists(client.cache_file):
        os.remove(client.cache_file)
    client._load()
    nvd_body = {"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "configurations": [
        {"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
             "versionStartIncluding": "2.4.49", "versionEndIncluding": "2.4.50"}
        ]}]}
    ]}}]}
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cveId"])
        return FakeResponse(200, body=nvd_body)

    client.session = types.SimpleNamespace(get=fake_get)
    ranges = client.get_ranges("CVE-2024-12345")
    assert ranges and ranges[0]["min"] == "2.4.49"
    assert ranges[0]["max"] == "2.4.50"
    # Повторный вызов идёт из кэша — без сети
    assert client.get_ranges("CVE-2024-12345") == ranges
    assert len(calls) == 1
    # Кэш сохранён на диск и перечитывается
    client2 = rt.NVDRangesClient()
    client2.cache_file = "/tmp/recon_test_nvd.json"
    client2._load()
    assert client2.get_ranges("CVE-2024-12345") == ranges
    os.remove("/tmp/recon_test_nvd.json")


def test_msf_checkcode_parsing():
    v = rt.PoCVerifier()
    assert v._parse_msf_check_output("CheckCode::Vulnerable (The target is exploitable)") == \
        ("vulnerable", "CheckCode::Vulnerable (target is exploitable)")
    assert v._parse_msf_check_output("CheckCode::Safe (No vulnerabilities found)")[0] == "not_vulnerable"
    assert v._parse_msf_check_output("CheckCode::Unknown")[0] == "unknown"
    # Строки без CheckCode падают в старые текстовые паттерны
    assert v._parse_msf_check_output("The target is vulnerable.")[0] == "vulnerable"


def test_nuclei_check_cve_no_nuclei():
    scanner = rt.NucleiScanner()
    # nuclei не установлен в песочнице — должен вернуть None, не падать
    if not rt.is_tool_installed("nuclei"):
        assert scanner.check_cve("http://example.com", "CVE-2021-44228") is None


def test_resume_state_roundtrip():
    os.makedirs("/tmp/recon_test_out", exist_ok=True)
    rt.save_resume_state("/tmp/recon_test_out", "example.com", "nmap",
                          {"ports": [80, 443]}, None)
    state = rt.load_resume_state("/tmp/recon_test_out", "example.com")
    assert state["stage"] == "nmap"
    assert state["results"]["ports"] == [80, 443]
    rt.clear_resume_state("/tmp/recon_test_out", "example.com")
    assert rt.load_resume_state("/tmp/recon_test_out", "example.com") is None


def test_html_report_generation():
    os.makedirs("/tmp/recon_test_out", exist_ok=True)
    results = {"target": "example.com", "ip": "1.2.3.4", "timestamp": "20260929",
               "os": {"name": "Linux"}, "detailed_ports": [
                   {"port": 80, "protocol": "tcp", "service": {"name": "http", "product": "nginx",
                                                               "version": "1.18", "banner": ""}}],
               "subdomains": ["www.example.com"]}
    poc_results = {"main": [
        {"vulnerability": "CVE-2021-41773", "target": "example.com", "status": "vulnerable",
         "confidence": 95, "epss": 0.9, "kev": True, "details": "Read /etc/passwd"},
        {"vulnerability": "CVE-2014-0160", "target": "example.com", "status": "not_vulnerable",
         "confidence": 40, "epss": 0.1, "kev": False, "details": "no leak"},
    ], "subdomains": {}, "hard_mode_subdomains": {}, "summary": {}}
    out = "/tmp/recon_test_out/report.html"
    rt.generate_html_report(results, poc_results, out)
    with open(out, encoding="utf-8") as f:
        html = f.read()
    assert "CVE-2021-41773" in html and "example.com" in html and "nginx" in html
    # Сортировка: high-confidence CVE идёт раньше low-confidence
    assert html.index("CVE-2021-41773") < html.index("CVE-2014-0160")
    assert "<script" not in html  # только статичный HTML, без скриптов


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
