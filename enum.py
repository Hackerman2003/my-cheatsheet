#!/usr/bin/env python3
"""
mauzo_enum.py
Non-destructive enumeration script for web apps (AJAX/PHP). Prints findings to stdout.
Run on Windows or Linux. Use responsibly (only against systems you own/authorize).

Dependencies:
    pip install requests beautifulsoup4 pymysql
(pymysql only required for the optional DB test)

Usage:
    python mauzo_enum.py https://mauzo.habaritechnology.com
"""

import sys
import re
import time
import json
import socket
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

# Optional DB test (import when needed)
try:
    import pymysql
except Exception:
    pymysql = None

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mauzo-enum/1.0"
DEFAULT_TIMEOUT = 8
MAX_WORKERS = 6

COMMON_PATHS = [
    "/.env", "/.env.example", "/.gitignore", "/.git/HEAD", "/.git/config",
    "/.git/index", "/.git/packed-refs", "/wp-config.php", "/composer.lock",
    "/vendor/composer/installed.json", "/config/database.php", "/backup.zip",
    "/backups/backup.zip", "/backup.tar.gz", "/backup.sql", "/.htpasswd",
    "/phpinfo.php"
]

JS_TOKEN_PATTERNS = [
    r"\.env", r"DB_PASSWORD", r"DB_USERNAME", r"API_KEY", r"api_key",
    r"AWS_ACCESS_KEY_ID", r"AWS_SECRET_ACCESS_KEY", r"BEGIN RSA PRIVATE KEY",
    r"ssh-rsa", r"token", r"csrf", r"session", r"password", r"passwd"
]

AJAX_PATTERNS = re.compile(
    r"(ajax\.php|admin-ajax\.php|/api/[A-Za-z0-9_/\-\.]+|/ajax/[A-Za-z0-9_/\-\.]+|index\.php\?action=[A-Za-z0-9_\-]+)",
    re.IGNORECASE
)


def safe_get(session, url, method="GET", **kwargs):
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects", True)
    try:
        if method == "GET":
            return session.get(url, **kwargs)
        elif method == "HEAD":
            return session.head(url, **kwargs)
    except requests.RequestException as e:
        print(f"[ERR] {method} {url} : {e}")
    return None


def probe_common_files(base_url):
    print("\n== Checking common files ==")
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        resp = safe_get(s, url, "GET")
        if resp is None:
            print(f"{path} -> (no response)")
            continue
        status = resp.status_code
        print(f"{path} -> HTTP {status}")
        # Print small snippet if it's a 200 and likely interesting
        if status == 200:
            text = resp.text.strip()
            snippet = text[:600].replace("\n", " ") if text else ""
            # show snippet only if it contains suspicious tokens
            if any(tok.lower() in snippet.lower() for tok in ["db_", "aws", ".env", "BEGIN", "PRIVATE KEY", "DB_PASSWORD", "API_KEY", "phpmyadmin"]):
                print("  Snippet:", snippet[:600])
            else:
                print("  (200 OK — no obvious secret tokens in first 600 chars)")


def check_git_exposure(base_url):
    print("\n== Checking for .git exposure ==")
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    for path in ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/packed-refs"]:
        url = urljoin(base_url, path)
        resp = safe_get(s, url, "GET")
        if resp and resp.status_code in (200, 302):
            print(f"{path} -> HTTP {resp.status_code}")
            # Print small content safely (text or hex preview)
            raw = resp.content
            try:
                txt = raw.decode("utf-8", errors="replace")
                print("  Content (first 400 chars):", txt[:400].replace("\n", " "))
            except Exception:
                print("  Binary content (first 64 bytes):", raw[:64].hex())


def fetch_robots_sitemap(base_url):
    print("\n== robots.txt and sitemap.xml ==")
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    for p in ["/robots.txt", "/sitemap.xml"]:
        url = urljoin(base_url, p)
        resp = safe_get(s, url, "GET")
        if resp and resp.status_code == 200:
            print(f"{p} -> HTTP 200")
            text = resp.text.strip()
            print(text[:800].replace("\n", " "))
        else:
            code = resp.status_code if resp else "no-response"
            print(f"{p} -> HTTP {code}")


def fetch_composer_installed(base_url):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    url = urljoin(base_url, "/vendor/composer/installed.json")
    resp = safe_get(s, url, "GET")
    if resp and resp.status_code == 200:
        print("\n== vendor/composer/installed.json found ==")
        try:
            j = resp.json()
            # installed.json structure varies; try to list package names
            pkgs = []
            if isinstance(j, dict) and "packages" in j:
                for p in j["packages"]:
                    name = p.get("name")
                    ver = p.get("version") or p.get("time")
                    pkgs.append(f"{name} {ver}")
            elif isinstance(j, list):
                for p in j:
                    name = p.get("name")
                    ver = p.get("version") or p.get("time")
                    pkgs.append(f"{name} {ver}")
            if pkgs:
                print("  Packages (sample 20):")
                for p in pkgs[:20]:
                    print("   -", p)
            else:
                print("  JSON parsed but no package list found")
        except Exception as e:
            print("  Failed to parse JSON:", e)
    else:
        print("\n== vendor/composer/installed.json -> not found or non-200")


def extract_js_urls(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    # script tags
    for s in soup.find_all("script", src=True):
        urls.add(urljoin(base_url, s["src"]))
    # link rel=preload or manifest might have JS
    for l in soup.find_all("link", href=True):
        href = l["href"]
        if href.endswith(".js"):
            urls.add(urljoin(base_url, href))
    return sorted(urls)


def scan_js_for_tokens(js_url):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    try:
        resp = safe_get(s, js_url, "GET")
        if not resp or resp.status_code != 200:
            return js_url, None, f"HTTP {resp.status_code if resp else 'no-response'}"
        content = resp.text
        findings = []
        for pat in JS_TOKEN_PATTERNS:
            if re.search(pat, content, re.IGNORECASE):
                findings.append(pat)
        # look for explicit-looking keys (rough heuristics)
        key_hits = re.findall(r"(?:API_KEY|apiKey|api_key|AWS_ACCESS_KEY_ID|aws_access_key_id)[^\"'=\s:]{0,60}", content, re.IGNORECASE)
        return js_url, findings or key_hits or [], None
    except Exception as e:
        return js_url, None, str(e)


def find_ajax_endpoints_from_home(base_url):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    resp = safe_get(s, base_url, "GET")
    if not resp or resp.status_code != 200:
        print(f"\nCannot fetch homepage: HTTP {resp.status_code if resp else 'no-response'}")
        return []
    html = resp.text
    matches = set(re.findall(AJAX_PATTERNS, html))
    # also extract via regex capturing whole urls/paths
    paths = set(re.findall(r'(["\'])(/api/[^"\']+|/ajax/[^"\']+|ajax\.php[^"\']*|admin-ajax\.php[^"\']*)\1', html, re.IGNORECASE))
    extracted = set()
    for m in paths:
        if isinstance(m, tuple):
            extracted.add(m[1])
        else:
            extracted.add(m)
    # parse scripts for endpoints (XHR/fetch usage roughly)
    scripts_hits = re.findall(r'fetch\(["\']([^"\']+)["\']', html)
    for si in scripts_hits:
        extracted.add(si)
    # absolute-ify and filter duplicates
    final = set()
    for p in extracted:
        final.add(urljoin(base_url, p))
    print("\n== AJAX / API endpoints discovered on homepage ==")
    for u in sorted(final):
        print(" -", u)
    return sorted(final)


def quick_js_scan(base_url):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    resp = safe_get(s, base_url, "GET")
    if not resp or resp.status_code != 200:
        print("Cannot fetch homepage for JS discovery.")
        return
    html = resp.text
    js_urls = extract_js_urls(base_url, html)
    if not js_urls:
        print("\nNo external JS files found on homepage (or none with src attrs).")
        return
    print("\n== Scanning JS files for token patterns ==")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(scan_js_for_tokens, u): u for u in js_urls}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                jsurl, findings, err = fut.result()
                if err:
                    print(f"{jsurl} -> ERR: {err}")
                elif findings:
                    print(f"{jsurl} -> FOUND: {findings}")
                else:
                    print(f"{jsurl} -> (no obvious tokens found)")
            except Exception as e:
                print(f"{url} -> exception: {e}")


def small_crawl(base_url, max_pages=30):
    """
    Lightweight crawl (HTML only) limited by domain and page count.
    Used to populate endpoints to scan locally (respects small depth).
    """
    print(f"\n== Lightweight crawl (max {max_pages} pages) ==")
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    to_visit = [base_url]
    seen = set()
    pages = 0
    endpoints = set()
    while to_visit and pages < max_pages:
        url = to_visit.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = safe_get(s, url, "GET")
        pages += 1
        if not resp or resp.status_code != 200:
            continue
        html = resp.text
        # find links
        soup = BeautifulSoup(html, "html.parser")
        # extract hrefs
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            # skip mailto/tel
            if href.startswith("mailto:") or href.startswith("tel:"):
                continue
            ab = urljoin(base_url, href)
            # restrict to same domain
            if urlparse(ab).netloc == urlparse(base_url).netloc:
                if ab not in seen and ab not in to_visit:
                    to_visit.append(ab)
        # collect probable API/ajax endpoints from page text
        raw_hits = re.findall(r'(?:/api/[A-Za-z0-9_/\-\.]+|/ajax/[A-Za-z0-9_/\-\.]+|ajax\.php[^"\s]+|admin-ajax\.php[^"\s]+|index\.php\?action=[A-Za-z0-9_\-]+)',
                              html, re.IGNORECASE)
        for h in raw_hits:
            endpoints.add(urljoin(base_url, h))
    print("Crawl collected endpoints (sample 50):")
    for e in list(endpoints)[:50]:
        print(" -", e)
    return list(endpoints)


def mysql_interactive_test(host, port, user, db=None):
    if not pymysql:
        print("\n[pymysql not installed] To enable DB test: pip install pymysql")
        return
    print("\n== MySQL interactive test ==")
    pw = input("Enter DB password (input will be visible): ").strip()
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=pw, database=db, connect_timeout=5)
        cur = conn.cursor()
        cur.execute("SHOW DATABASES;")
        print("Databases:")
        for row in cur.fetchall()[:20]:
            print(" -", row[0])
        conn.close()
    except pymysql.err.OperationalError as e:
        print("MySQL connection failed:", e)
    except Exception as e:
        print("MySQL error:", e)


def tcp_port_check(host, port=3306):
    print(f"\n== TCP check {host}:{port} ==")
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            print("Port open")
    except Exception as e:
        print("Port closed / unreachable:", e)


def main():
    if len(sys.argv) < 2:
        print("Usage: python mauzo_enum.py https://mauzo.habaritechnology.com")
        sys.exit(1)
    base = sys.argv[1].strip().rstrip("/")
    parsed = urlparse(base)
    if not parsed.scheme:
        print("Please include the scheme (https://).")
        sys.exit(1)

    print(f"Target: {base}")
    start = time.time()

    # quick probes
    probe_common_files(base)
    check_git_exposure(base)
    fetch_robots_sitemap(base)
    fetch_composer_installed(base)

    # discover endpoints and JS
    endpoints = find_ajax_endpoints_from_home(base)
    quick_js_scan(base)

    # lightweight crawl to find endpoints (safe, limited)
    more_endpoints = small_crawl(base, max_pages=20)
    endpoints = sorted(set(endpoints + more_endpoints))

    # run quick HTTP HEAD on discovered endpoints (conservative)
    if endpoints:
        print("\n== HEAD check on discovered endpoints ==")
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(s.head, u, timeout=DEFAULT_TIMEOUT, allow_redirects=True): u for u in endpoints[:60]}
            for fut in as_completed(futures):
                u = futures[fut]
                try:
                    r = fut.result()
                    print(f"{u} -> {r.status_code}")
                except Exception as e:
                    print(f"{u} -> ERR: {e}")

    # optional DB checks
    do_db = input("\nDo you want to run DB connectivity checks? (y/N): ").strip().lower()
    if do_db == "y":
        host = input("DB host/IP (default 5.189.146.225): ").strip() or "5.189.146.225"
        port = int(input("DB port (default 3306): ").strip() or 3306)
        user = input("DB user (default haba_mauzo_user): ").strip() or "haba_mauzo_user"
        db = input("DB name (optional, press Enter to skip): ").strip() or None
        tcp_port_check(host, port)
        mysql_interactive_test(host, port, user, db)

    duration = time.time() - start
    print(f"\nDone. Duration: {duration:.1f}s — results printed above. Rotate any leaked keys immediately.")

if __name__ == "__main__":
    main()
