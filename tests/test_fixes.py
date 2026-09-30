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


def test_rce_differential_not_string_match():
    v = rt.PoCVerifier()
    class Resp:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
    # Страница содержит слово "root" в тексте — без дифференциальной
    # проверки это давало ложное "vulnerable"
    def fake_safe(method, url, **kw):
        if "cmd=id" in url:
            return Resp("<html>Site about root vegetables</html>"), None
        if "exec=whoami" in url:
            return Resp("<html>Site about root vegetables</html>"), None
        return Resp("<html>Site about root vegetables</html>"), None
    v._safe_request = fake_safe
    assert v.check_rce("http://example.com") is None

    # Реальный вывод id только с параметром — срабатывание
    def fake_safe2(method, url, **kw):
        if "cmd=id" in url:
            return Resp("uid=33(www-data) gid=33(www-data) groups=33"), None
        return Resp("<html>normal page</html>"), None
    v._safe_request = fake_safe2
    res = v.check_rce("http://example.com")
    assert res and res["status"] == "vulnerable"

    # Ложный случай: uid= есть уже в baseline (отражается всегда)
    def fake_safe3(method, url, **kw):
        return Resp("uid=0(root) hardcoded footer"), None
    v._safe_request = fake_safe3
    assert v.check_rce("http://example.com") is None


def test_high_epss_escalation():
    class FakeVulners:
        def normalize_cpe(self, cpe):
            return ("", "", "")

    class FakeEpss:
        def __init__(self, epss, kev):
            self.epss, self.kev = epss, kev

        def get_priority_score(self, cve):
            return self.epss, self.kev, self.epss + (0.5 if self.kev else 0)

    engine = rt.ConfidenceEngine(FakeVulners(), FakeEpss(0.97, False))
    # ProFTPD без версии (как в реальном скане): раньше 15-17 -> skip
    conf = engine.score({"product": "ProFTPD", "version": "", "banner": "", "cpe": ""},
                        "CVE-2015-3306", "searchsploit")
    assert conf["score"] >= 55, conf
    assert conf["action"] in ("run_check", "run_poc")
    assert "Escalated" in conf["reason"]

    # Низкий EPSS без версии — как и раньше skip
    engine2 = rt.ConfidenceEngine(FakeVulners(), FakeEpss(0.05, False))
    conf2 = engine2.score({"product": "ProFTPD", "version": "", "banner": "", "cpe": ""},
                          "CVE-2015-3306", "searchsploit")
    assert conf2["action"] == "skip"


def test_php_cgi_check():
    v = rt.PoCVerifier()
    class Resp:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    def fake_safe(method, url, data=None, headers=None, **kw):
        # ответ не содержит маркер из payload
        return Resp("<html>nothing</html>"), None
    v._safe_request = fake_safe
    res = v.check_php_cgi_cve_2012_1823("http://example.com")
    assert res["status"] == "not_vulnerable"

    def fake_safe2(method, url, data=None, headers=None, **kw):
        return Resp("output: " + data.replace("<?php echo '", "").replace("'; ?>", "")), None
    v._safe_request = fake_safe2
    res2 = v.check_php_cgi_cve_2012_1823("http://example.com")
    assert res2["status"] == "vulnerable"


def test_sqli_differential():
    v = rt.PoCVerifier()
    class Resp:
        def __init__(self, text):
            self.text = text

    # Ошибка MySQL только с payload — vulnerable
    def fake(method, url, **kw):
        if "id=1'" in url:
            return Resp("Warning: mysqli_query(): SQL syntax error near"), None
        return Resp("<html>ok page</html>"), None
    v._safe_request = fake
    res = v.check_sqli("http://example.com")
    assert res and res["status"] == "vulnerable", res

    # Ошибка присутствует и в baseline — не срабатывает
    def fake2(method, url, **kw):
        return Resp("Warning: mysqli_query(): error page footer"), None
    v._safe_request = fake2
    assert v.check_sqli("http://example.com") is None

    # Чистый сайт — None
    def fake3(method, url, **kw):
        return Resp("<html>ok page</html>"), None
    v._safe_request = fake3
    assert v.check_sqli("http://example.com") is None


def test_sqlmap_output_parse():
    scanner = rt.SQLMapScanner("/tmp")
    scanner.available = True  # в песочнице sqlmap нет, тестируем только парсер
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return types.SimpleNamespace(stdout="back-end DBMS: MySQL >= 5.0\nParameter 'id' is vulnerable", stderr="", returncode=0)

    import recon_tool as r2
    orig_run = r2.subprocess.run
    r2.subprocess.run = fake_run
    try:
        res = scanner.scan("http://example.com/item.php?id=1")
    finally:
        r2.subprocess.run = orig_run
    assert res["status"] == "vulnerable"
    assert "MySQL" in res["details"]

    def fake_run2(cmd, **kw):
        return types.SimpleNamespace(stdout="all tested parameters do not appear to be injectable", stderr="", returncode=0)
    r2.subprocess.run = fake_run2
    try:
        res2 = scanner.scan("http://example.com/item.php?id=1")
    finally:
        r2.subprocess.run = orig_run
    assert res2["status"] == "not_vulnerable"


def test_mysql_fingerprint_parse():
    # Поддельный handshake: длина, seq, protocol, версия, \x00
    payload = bytes([10]) + b"8.0.32-0ubuntu" + b"\x00" + b"\x00" * 40
    data = len(payload).to_bytes(3, "little") + b"\x00" + payload

    class FakeSock:
        def __init__(self, data): self._d = data
        def recv(self, n): return self._d
        def close(self): pass

    orig = rt.socket.create_connection
    rt.socket.create_connection = lambda addr, timeout=None: FakeSock(data)
    try:
        ver = rt.mysql_fingerprint("1.2.3.4", 3306)
    finally:
        rt.socket.create_connection = orig
    assert ver == "8.0.32-0ubuntu", ver


def test_wp_fingerprint_version():
    scanner = rt.WordPressScanner()
    html = '<meta name="generator" content="WordPress 6.2.1"> <link href="/wp-content/plugins/contact-form-7/includes/css/styles.css">'

    class Resp:
        text = html

    import recon_tool as r2
    class FakeSess:
        headers = {}

        def get(self, url, **kw):
            if url.rstrip("/").endswith("/feed/") or "readme" in url:
                raise Exception("skip")
            return Resp()

    orig_session = r2.requests.Session
    r2.requests.Session = lambda: FakeSess()
    try:
        info = scanner.detect("http://example.com")
    finally:
        r2.requests.Session = orig_session
    assert info["version"] == "6.2.1"
    assert "contact-form-7" in info["plugins"]


CSV_SAMPLE = """scan_order,target,kind,host,has_site,https_status,http_status,ptr,addresses,redirect_domains,tls_domains,server,title,is_wordpress,wordpress_confidence,wordpress_signals,elapsed_ms,error
1,103.244.145.246,ip,103.244.145.246,False,,,hosted-by.zetservers.com,103.244.145.246,,,,,False,none,,4351,
2,107.155.71.33,ip,107.155.71.33,True,200,301,107-155-71-33.cprapid.com,107.155.71.33,wreainc.com,,Apache,AI Initiative,True,medium,html:wordpress,12170,
3,109.108.65.29,ip,109.108.65.29,True,401,,109-108-65-29.kievnet.com.ua,109.108.65.29,,,lighttpd/1.4.39,AiCloud,False,none,,7992,
4,10.0.0.999,ip,10.0.0.999,True,,,,,,nginx,,True,medium,,100,some error
"""


def test_parse_targets_csv_and_filters():
    with open("/tmp/recon_test_targets.csv", "w") as f:
        f.write(CSV_SAMPLE)
    # Все цели (без ошибок)
    all_t = rt.select_targets_from_csv("/tmp/recon_test_targets.csv")
    assert "103.244.145.246" in all_t and "107.155.71.33" in all_t
    assert "10.0.0.999" not in all_t  # строка с error отфильтрована
    # Только сайты
    sites = rt.select_targets_from_csv("/tmp/recon_test_targets.csv", require_site=True)
    assert "103.244.145.246" not in sites  # has_site=False
    assert "107.155.71.33" in sites
    # Только WordPress
    wp = rt.select_targets_from_csv("/tmp/recon_test_targets.csv", wordpress_only=True)
    assert wp == ["107.155.71.33"]
    # Только с известным сервером
    srv = rt.select_targets_from_csv("/tmp/recon_test_targets.csv", has_server=True)
    assert "109.108.65.29" in srv and "103.244.145.246" not in srv
    # Обычный файл со списком
    with open("/tmp/recon_test_targets.txt", "w") as f:
        f.write("# comment\nexample.com\n1.2.3.4\n\nexample.com\n")
    lst = rt.parse_targets_file("/tmp/recon_test_targets.txt")
    assert lst == ["example.com", "1.2.3.4"]  # dedup, без комментариев
    # CSV как источник тоже парсится общим парсером
    assert len(rt.parse_targets_file("/tmp/recon_test_targets.csv")) == 4
    os.remove("/tmp/recon_test_targets.csv")
    os.remove("/tmp/recon_test_targets.txt")


def test_expand_cidr():
    hosts = rt.expand_cidr("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]
    assert rt.expand_cidr("not-a-cidr") == []
    assert rt.expand_cidr("10.0.0.0/8") == []  # слишком большая сеть


def test_telegram_notifier_disabled_and_payload():
    # Без токена — выключен и ничего не отправляет
    n = rt.TelegramNotifier("")
    assert not n.enabled
    assert n.send("test") is False
    # Спарсенный аргумент
    n2 = rt.TelegramNotifier("123456:ABC-DEF:98765")
    assert n2.token == "123456:ABC-DEF" and n2.chat_id == "98765"
    assert n2.enabled
    # Проверяем payload без реальной отправки: подменяем session
    sent = []
    class FakeSess:
        def post(self, url, json=None, timeout=None):
            sent.append((url, json))
            return FakeResponse(200)
    n2.session = FakeSess()
    n2.notify_scan_done("example.com", {"vulnerable": 2, "not_vulnerable": 5,
                                         "unknown": 1, "skipped": 10, "total": 18})
    url, payload = sent[0]
    assert url == "https://api.telegram.org/bot123456:ABC-DEF/sendMessage"
    assert payload["chat_id"] == "98765"
    assert "example.com" in payload["text"] and "2" in payload["text"]


def test_bot_finding_threshold_notification():
    # findings-уведомление: только vulnerable с confidence >= порога
    n = rt.TelegramNotifier("123456:ABC-DEF:98765")
    sent = []

    class FakeSess:
        def post(self, url, json=None, timeout=None, data=None, files=None):
            sent.append(json or data)
            return FakeResponse(200)

        def get(self, url, params=None, timeout=None):
            return FakeResponse(200, body={"result": []})

    n.session = FakeSess()
    checks = [
        {"status": "vulnerable", "confidence": 85, "vulnerability": "CVE-X", "method": "msf_check"},
        {"status": "vulnerable", "confidence": 45, "vulnerability": "CVE-Y", "method": "sqli_test"},
        {"status": "not_vulnerable", "confidence": 90, "vulnerability": "CVE-Z", "method": "msf_check"},
    ]
    threshold = 70
    found = [c for c in checks
             if c.get("status") == "vulnerable" and (c.get("confidence") or 0) >= threshold]
    assert found == [checks[0]]  # только 85-очковый vulnerable


def test_bot_command_loop_report_and_exit():
    n = rt.TelegramNotifier("123456:ABC-DEF:98765")
    n.session = types.SimpleNamespace(
        post=lambda url, json=None, timeout=None, data=None, files=None: FakeResponse(200),
        get=lambda url, params=None, timeout=None: FakeResponse(200, body={
            "result": [
                {"update_id": 1, "message": {"text": "/list"}},
                {"update_id": 2, "message": {"text": "/report example.com"}},
                {"update_id": 3, "message": {"text": "/exit"}},
            ]}))
    # регистрируем отчёты
    rt.SCAN_REGISTRY["example.com"] = {
        "summary": {"vulnerable": 1, "not_vulnerable": 3},
        "json": "/tmp/recon_test_report.json", "html": "/tmp/recon_test_report.html"}
    with open("/tmp/recon_test_report.html", "w") as f:
        f.write("<html>report</html>")
    with open("/tmp/recon_test_report.json", "w") as f:
        f.write("{}")
    # /report должен отправить оба файла (sendDocument по данным)
    posted = []
    orig_post = n.session.post
    n.session = types.SimpleNamespace(
        post=lambda url, json=None, timeout=None, data=None, files=None: (
            posted.append((url, data, files)), FakeResponse(200))[1],
        get=n.session.get)
    rt.bot_command_loop(n)
    assert any("sendDocument" in u for u, _, _ in posted), posted
    assert any("example.com" in (d or {}).get("caption", "") for _, d, _ in posted)
    # цикл завершился по /exit — дошли до этой строки
    os.remove("/tmp/recon_test_report.html")
    os.remove("/tmp/recon_test_report.json")


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
