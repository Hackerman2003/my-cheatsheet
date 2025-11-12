### Comprehensive Guide to Feroxbuster and Gobuster

Feroxbuster and Gobuster are essential tools for web reconnaissance, specifically for directory/file brute-forcing (forced browsing) to discover hidden endpoints on web applications. Both are fast, multi-threaded, and support recursion, extensions, and custom configurations. This guide covers installation, basic usage, **every command-line option** (flags), advanced features, examples, and best practices. All information is based on the latest versions as of November 2025 (Feroxbuster v2.11.0+ and Gobuster v3+). Use these ethically in authorized environments only.

#### Feroxbuster
Feroxbuster is a Rust-based tool focused on recursive content discovery with smart auto-tuning, wildcard filtering, and response analysis. It's particularly strong for deep scans and collecting artifacts like words/extensions from responses.

##### Installation
Feroxbuster supports multiple methods for easy setup across platforms:
- **Pre-built Binaries**: Download from GitHub Releases (https://github.com/epi052/feroxbuster/releases). Extract and add to PATH.
- **Package Managers**:
  - Debian/Ubuntu/Kali: `sudo apt install feroxbuster`.
  - Arch Linux: Use AUR (`yay -S feroxbuster`).
  - BlackArch: `sudo pacman -S feroxbuster`.
  - macOS (Homebrew): `brew install feroxbuster`.
  - Windows (Chocolatey): `choco install feroxbuster`; (Winget): `winget install epi052.feroxbuster`.
  - Snap: `sudo snap install feroxbuster`.
- **Build from Source**: Requires Rust/Cargo: `git clone https://github.com/epi052/feroxbuster.git && cd feroxbuster && cargo build --release`.
- **Docker**: `docker pull ghcr.io/epi052/feroxbuster:latest` (run with mounted wordlists).

Verify: `feroxbuster -V`.

##### Basic Usage
Basic syntax: `feroxbuster -u <TARGET_URL> -w <WORDLIST> [OPTIONS]`.

- Target a site: `feroxbuster -u http://example.com -w /path/to/wordlist.txt`.
- Output results: Add `-o output.txt`.

##### All Command-Line Options
Here's every flag, with descriptions and defaults (grouped by category for clarity):

| Flag | Description | Default |
|------|-------------|---------|
| **Help & Info** | | |
| `-h, --help` | Print help summary. | - |
| `-V, --version` | Print version info. | - |
| `-U, --update` | Update to latest version. | - |
| **Targets & Inputs** | | |
| `-u, --url <URL>` | Target URL (required unless stdin/resume). | - |
| `--stdin` | Read URLs from STDIN. | - |
| `--resume-from <STATE_FILE>` | Resume scan from state file (e.g., ferox-*.state). | - |
| `--request-file <REQUEST_FILE>` | Use raw HTTP request file as template. | - |
| `--protocol <PROTOCOL>` | Protocol for request-file or domain-only URL (http/https). | https |
| `--burp` | Auto-set proxy to Burp (127.0.0.1:8080) and --insecure. | - |
| `--burp-replay` | Auto-set replay-proxy to Burp and --insecure. | - |
| **Requests** | | |
| `-p, --proxy <PROXY>` | Proxy URL (http(s)/socks5(h)). | - |
| `-P, --replay-proxy <REPLAY_PROXY>` | Proxy for unfiltered requests only. | - |
| `-R, --replay-codes <STATUS_CODES>` | Codes to replay via proxy (comma-separated). | Value of --status-codes |
| `-a, --user-agent <UA>` | Custom User-Agent string. | feroxbuster/2.11.0 |
| `-A, --random-agent` | Random User-Agent from list. | - |
| `-x, --extensions <EXTS>` | File extensions (comma or @file). | - |
| `-m, --methods <METHODS>` | HTTP methods (e.g., GET,POST). | GET |
| `--data <DATA>` | Request body (@file supported). | - |
| `-H, --headers <HEADER>` | Custom headers (e.g., -H "Auth: token"). | - |
| `-b, --cookies <COOKIE>` | Cookies (e.g., -b session=abc). | - |
| `-Q, --query <QUERY>` | Query params (e.g., -Q key=value). | - |
| `-f, --add-slash` | Append / to URLs. | - |
| **Filtering** | | |
| `-S, --filter-size <SIZE>` | Filter response sizes (comma-separated). | - |
| `-X, --filter-regex <REGEX>` | Filter by regex on body/headers. | - |
| `-W, --filter-words <WORDS>` | Filter by word count. | - |
| `-N, --filter-lines <LINES>` | Filter by line count. | - |
| `-C, --filter-status <CODES>` | Deny-list status codes. | - |
| `--filter-similar-to <URL>` | Filter pages similar to given URL. | - |
| `-s, --status-codes <CODES>` | Allow-list status codes. | All |
| `--dont-scan <URL/REGEX>` | Exclude URLs/patterns from scanning. | - |
| **Performance & Limits** | | |
| `-T, --timeout <SEC>` | Request timeout. | 7 |
| `-r, --redirects` | Follow redirects. | - |
| `-k, --insecure` | Skip TLS validation. | - |
| `--server-certs <CERT>` | Custom root CA certs (PEM/DER). | - |
| `--client-cert <CERT>`, `--client-key <KEY>` | mTLS cert/key (PEM). | - |
| `-t, --threads <NUM>` | Concurrent threads. | 50 |
| `-n, --no-recursion` | Disable recursion. | - |
| `-d, --depth <DEPTH>` | Max recursion depth (0=infinite). | 4 |
| `--force-recursion` | Recurse on all endpoints (respects depth). | - |
| `--dont-extract-links` | Skip link extraction from responses. | - |
| `-L, --scan-limit <LIMIT>` | Max concurrent scans. | 0 (unlimited) |
| `--parallel <SCANS>` | Parallel instances for stdin URLs. | - |
| `--rate-limit <RPS>` | Requests/sec per directory. | 0 (unlimited) |
| `--time-limit <DURATION>` | Total scan time (e.g., 10m). | - |
| **Wordlists & Collection** | | |
| `-w, --wordlist <FILE/URL>` | Path/URL to wordlist. | - |
| `--auto-tune` | Auto-reduce rate on errors. | - |
| `--auto-bail` | Stop on excessive errors. | - |
| `-D, --dont-filter` | Disable wildcard auto-filter. | - |
| `--scan-dir-listings` | Recurse into dir listings. | - |
| `-E, --collect-extensions` | Auto-collect and add extensions. | - |
| `-B, --collect-backups <EXTS>` | Backup exts to probe (e.g., .bak). | ~, .bak, .bak2, .old, .1 |
| `-g, --collect-words` | Collect words from responses for wordlist. | - |
| `-I, --dont-collect <EXTS>` | Ignore exts when collecting. | - |
| **Output & Logging** | | |
| `-v, --verbosity <LEVEL>` | Verbosity (up to -vvvv). | - |
| `--silent` | Only print URLs (or JSON). | - |
| `-q, --quiet` | Hide progress/banners. | - |
| `--json` | JSON output to files. | - |
| `-o, --output <FILE>` | Results file. | - |
| `--debug-log <FILE>` | Debug log file. | - |
| `--no-state` | Disable .state files. | - |
| `--limit-bars <NUM>` | Max progress bars shown. | Unlimited |
| **Presets** | | |
| `--smart` | Enable auto-tune, collect-words, collect-backups. | - |
| `--thorough` | --smart + collect-extensions, scan-dir-listings. | - |

##### Advanced Features
- **Recursion**: Controlled by `--depth` and `--force-recursion`; extracts links automatically unless `--dont-extract-links`.
- **Wordlists**: Supports local files or remote URLs; auto-collects words (`--collect-words`) for dynamic lists.
- **Extensions**: Manual via `-x` or auto-discover (`--collect-extensions`); backups via `--collect-backups`.
- **Output Formats**: Plain text or JSON (`--json`); state files for resuming; debug logs.
- **Filtering**: Advanced regex/size/word/line/status filters; wildcard detection; similarity-based filtering.
- **Collection & Auto-Tuning**: Gathers artifacts (words, exts, backups) mid-scan; auto-adjusts rate on errors.
- **mTLS & Proxies**: Full support for custom certs, SOCKS/HTTP proxies, and replay proxies (e.g., for Burp).
- **Parallelism**: `--parallel` for multi-URL scans; rate-limiting per directory.

##### Examples
- Basic dir bust: `feroxbuster -u http://example.com -w common.txt -t 100 -o results.txt`.
- Recursive with extensions: `feroxbuster -u https://example.com -w dirs.txt -x php,html,js -d 3 --add-slash`.
- Proxy via Burp: `feroxbuster -u http://target.com --burp -w wordlist.txt -s 200,301`.
- Auto-collect & tune: `feroxbuster -u http://example.com --smart -w raft-medium-directories.txt --output json.json --json`.
- Resume scan: `feroxbuster --resume-from ferox-123.state`.
- POST with data: `feroxbuster -u http://example.com -m POST --data '{"key":"value"}' -w payloads.txt`.
- Filter & limit: `feroxbuster -u http://example.com -w list.txt -C 404 -S 0 -t 20 --rate-limit 10 --time-limit 5m`.
- IPv6 non-recursive: `feroxbuster -u http://[::1] -n -vv -w small.txt`.
- Parallel stdin: `echo -e "http://site1.com\nhttp://site2.com" | feroxbuster --stdin --parallel 2 -w wordlist.txt`.

##### Tips & Best Practices
- Start with small wordlists (e.g., raft-small-directories.txt) and low threads (10-20) to avoid bans.
- Use `--auto-tune` for production sites; monitor errors with `-v`.
- Combine with tools like `fff` for filtering: `feroxbuster ... | fff -s 200`.
- For large scans, use `--scan-limit` to cap concurrency (e.g., threads × limit = total reqs).
- Respect robots.txt indirectly via exclusions; always get permission.
- Update regularly: `feroxbuster -U`.
- JSON output (`--json`) for parsing/automation.

#### Gobuster
Gobuster (v3) is a Go-based brute-forcer with modes for dirs, DNS, vhosts, S3/GCS, TFTP, and fuzzing. It's lightweight, supports patterns, and handles wildcards well.

##### Installation
- **Go Install** (recommended, Go 1.24+): `go install github.com/OJ/gobuster/v3@latest`. Add `$GOPATH/bin` to PATH.
- **Binaries**: Download from GitHub Releases (https://github.com/OJ/gobuster/releases).
- **Docker**: `docker pull ghcr.io/oj/gobuster:latest`.
- **Build from Source**: `git clone https://github.com/OJ/gobuster.git && cd gobuster && go mod tidy && go build`.
- Verify: `gobuster version`.

##### Basic Usage
Syntax: `gobuster <MODE> [OPTIONS]`.

- Basic dir: `gobuster dir -u http://example.com -w wordlist.txt`.

##### All Command-Line Options
Global unless mode-specific:

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL (dir/vhost/fuzz). | - |
| `-w` | Wordlist file (required). | - |
| `-x` | Extensions (comma-sep or @file). | - |
| `-t` | Threads. | Varies by mode |
| `-o` | Output file. | - |
| `-q` | Quiet (no progress). | - |
| `-l` | Show response lengths. | - |
| `-s` | Include status codes (comma/range). | - |
| `-H` | Custom headers. | - |
| `-c` | Cookies. | - |
| `-a` | User-Agent. | gobuster/v3.x |
| `-r` | Custom DNS server (dns mode). | - |
| `-do` | Domain (dns mode). | - |
| `--append-domain` | Append domain to vhosts. | - |
| `--timeout` | HTTP timeout (sec). | 10 |
| `--delay` | Delay between reqs (sec). | 0 |
| `--debug` | Debug output. | - |
| `--force` | Ignore pre-check errors (dir). | - |
| `--no-progress` | Disable progress. | - |
| `-p` | Pattern file ({GOBUSTER} placeholder). | - |
| `-d` | POST data (fuzz). | - |
| `-s` | Target server (tftp). | - |
| `-v` | Verbose/color output. | - |
| `--exclude-length` | Exclude response lengths. | - |
| `--exclude-hostname-length` | Exclude hostname lengths (dns). | - |
| `--wildcard` | Force wildcard handling (dns). | - |
| `--random-agent` | Random User-Agent. | - |
| `--proxy` | Proxy URL. | - |
| `--insecure` | Skip TLS verify. | - |
| `--add-slash` | Append / (dir). | - |
| `--expand` | Expand slashes in wordlist (dir). | - |
| `--trim` | Trim right whitespace in wordlist. | - |
| `--offset` | Skip N lines in wordlist. | 0 |
| `--retry` | Retry failed reqs. | 0 |
| `--retry-status` | Status codes to retry. | - |
| `--timeout` | Per-req timeout. | - |
| `--delay` | Delay (sec or duration). | - |
| `--stall-timeout` | Stall detection timeout. | - |
| `--client-cert` | mTLS client cert. | - |
| `--client-key` | mTLS client key. | - |
| `--ca-cert` | CA cert. | - |
| `--write-cookies` | Save cookies to file. | - |
| `--cookie-jar` | Cookie jar file. | - |
| `--header-fuzzing` | Fuzz headers (fuzz mode). | - |
| `--url-encode` | URL-encode payloads. | - |
| `--wildcard-forced` | Force wildcard (dir). | - |
| `--no-fallback` | Disable fallback on 404s. | - |
| `--sitemap-sort` | Sort sitemap output. | - |

Mode-specific: Use `gobuster <mode> ...` (e.g., dir, dns, vhost, s3, gcs, tftp, fuzz, sitemap).

##### Advanced Features
- **Modes**: dir (web files), dns (subdomains), vhost (virtual hosts), s3/gcs (buckets), tftp (files), fuzz (params/headers/POST).
- **Wordlists**: Supports # comments; offset with `--offset`; tech-specific (e.g., subdomains-top1mil.txt).
- **Extensions**: `-x` for files; auto from patterns.
- **Recursion**: Not native (use dir mode iteratively); pair with tools like gospider.
- **Output**: File dumps; quiet/verbose; auto-no-progress on redirect.
- **Fuzzing**: Replace FUZZ in URLs/POST/headers; patterns for complex payloads.
- **Cloud & DNS**: S3/GCS bucket enum; wildcard DNS handling; custom resolvers.
- **mTLS & Proxies**: Full TLS support; proxies with auth.

##### Examples
- Dir enum: `gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html -t 50 -o out.txt`.
- DNS subs: `gobuster dns -do example.com -w subdomains.txt -r 8.8.8.8:53 -t 50 --wildcard`.
- VHost: `gobuster vhost -u https://example.com -w vhosts.txt --append-domain -t 100 -s 200,204,301,302,307,308`.
- S3 buckets: `gobuster s3 -w buckets.txt --endpoint-url https://s3.amazonaws.com`.
- Fuzz URL param: `gobuster fuzz -u https://example.com/?file=FUZZ -w files.txt -t 20`.
- POST fuzz: `gobuster fuzz -u https://example.com -w users.txt -d 'username=FUZZ&password=pass' --proxy http://127.0.0.1:8080`.
- GCS: `gobuster gcs -w buckets.txt`.
- TFTP: `gobuster tftp -s 192.168.1.1 -w files.txt`.
- Verbose dir with filters: `gobuster dir -u http://target.com -w biglist.txt -s 200 -l --exclude-length 0,1234 -v`.

##### Tips & Best Practices
- Low threads initially (`-t 10`) to evade WAFs; increase gradually.
- Use targeted lists (e.g., SecLists for web); trim with `--trim`.
- Filter noise: `-s 200,301` and `-l` for clean output.
- For DNS, test wildcards first; use `--wildcard-forced` if needed.
- Docker for isolation: Mount wordlists as volumes.
- Chain with other tools: `gobuster ... | grep -v 404 > clean.txt`.
- Retry on flakes: `--retry 3 --retry-status 500`.
- Always scope: Start broad, then deep-dive findings.

### Updated Comprehensive Guide to Feroxbuster and Gobuster (Nov 2025 Edition)

Yo bro, trust received—I'm bumping this up with the latest deets as of November 12, 2025. Pulled fresh intel: Feroxbuster's at v2.12.0 (dropped Sept '24 with response size limiting), Gobuster's holding strong at v3.8.2 (with 2024-25 tweaks like dynamic length exclusion and Host fuzzing). Added new features, wordlist recs, pitfalls, integrations (tying back to SQLMap vibes), a comparison table, and extra examples/scripts. Kept it detailed but skimmable—let's level up your recon game.

#### Feroxbuster (v2.12.0)
Rust-powered beast for recursive forced browsing. New in v2.12: `--response-size-limit` to cap massive responses (e.g., avoid 10MB JSON dumps eating your RAM). Docs moved to a dedicated site, but core stays snappy with auto-tuning and artifact collection.

##### Installation (Updated)
- **Kali/Debian**: `sudo apt update && sudo apt install -y feroxbuster` (auto v2.12+).
- **Arch/BlackArch**: `sudo pacman -S feroxbuster`.
- **macOS (Brew)**: `brew install feroxbuster`.
- **Windows**: Winget `winget install epi052.feroxbuster` or Choco `choco install feroxbuster`. For manual: Grab ZIP from releases, extract, `feroxbuster.exe -V`.
- **Nix/Universal Script**: `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s $HOME/.local/bin`.
- **Docker**: `docker pull ghcr.io/epi052/feroxbuster:2.12.0`.
- **Update**: `./feroxbuster --update` (self-heals to latest).
- Pro Tip: On air-gapped setups, build from source: `git clone https://github.com/epi052/feroxbuster.git && cargo build --release`.

Verify: `feroxbuster -V` (should spit v2.12.0).

##### All Command-Line Options (Full List, v2.12)
Pulled from latest README/docs—grouped for sanity. Defaults in parens.

**Help/Info**:
- `-h/--help`: Help menu.
- `-V/--version`: Version info.
- `-U/--update`: Auto-update tool.

**Targets/Inputs**:
- `-u/--url <URL>`: Base URL (req'd). (None)
- `--stdin`: URLs from STDIN.
- `--resume-from <FILE>`: Resume from .state file.
- `--request-file <FILE>`: Raw HTTP request template.
- `--protocol <http|https>`: For request-file/domain-only. (https)
- `--burp`: Proxy to Burp (127.0.0.1:8080) + --insecure.
- `--burp-replay`: Replay proxy to Burp + --insecure.

**Requests**:
- `-p/--proxy <URL>`: HTTP/SOCKS5 proxy. (None)
- `-P/--replay-proxy <URL>`: Unfiltered proxy.
- `-R/--replay-codes <CODES>`: Replay specific codes. (Matches --status-codes)
- `-a/--user-agent <STR>`: Custom UA. (feroxbuster/2.12.0)
- `-A/--random-agent`: Random UA from list.
- `-x/--extensions <EXTS>`: Comma/@file exts (e.g., php,js). (None)
- `-m/--methods <METHODS>`: HTTP methods (GET,POST,...). (GET)
- `--data <DATA>`: Body data (@file). (None)
- `-H/--headers <HDR>`: Custom headers (multi). (None)
- `-b/--cookies <STR>`: Cookies. (None)
- `-Q/--query <QUERY>`: Query params (key=val). (None)
- `-f/--add-slash`: Append / to non-file URLs.

**Filtering**:
- `-S/--filter-size <SIZES>`: Filter response sizes (comma). (None)
- `-X/--filter-regex <REGEX>`: Body/header regex filter. (None)
- `-W/--filter-words <NUM>`: Word count filter. (None)
- `-N/--filter-lines <NUM>`: Line count filter. (None)
- `-C/--filter-status <CODES>`: Deny-list codes. (None)
- `--filter-similar-to <URL>`: Filter similar to baseline URL.
- `-s/--status-codes <CODES>`: Allow-list codes. (All)
- `--dont-scan <URL|REGEX>`: Exclude from recursion.
- **New v2.12**: `--response-size-limit <BYTES>`: Cap response size (e.g., 1M) to skip huge pages.

**Performance/Limits**:
- `-T/--timeout <SEC>`: Req timeout. (7s)
- `-r/--redirects`: Follow 3xx.
- `-k/--insecure`: Skip TLS verify.
- `--server-certs <CERT>`: Root CA PEM/DER.
- `--client-cert <CERT> --client-key <KEY>`: mTLS.
- `-t/--threads <NUM>`: Concurrency. (50)
- `-n/--no-recursion`: Disable recursion.
- `-d/--depth <NUM>`: Max depth (0=inf). (4)
- `--force-recursion`: Recurse everything.
- `--dont-extract-links`: Skip link extraction.
- `-L/--scan-limit <NUM>`: Max concurrent scans. (Unlimited)
- `--parallel <NUM>`: Parallel stdin URLs. (1)
- `--rate-limit <RPS>`: Req/sec per dir. (Unlimited)
- `--time-limit <DUR>`: Total time (e.g., 10m). (None)
- `--auto-tune`: Auto-throttle on errors.
- `--auto-bail`: Bail on too many errors.

**Wordlists/Collection**:
- `-w/--wordlist <FILE|URL>`: Wordlist path/URL. (Req'd)
- `-D/--dont-filter`: Skip wildcard filter.
- `--scan-dir-listings`: Recurse dir indexes.
- `-E/--collect-extensions`: Auto-add discovered exts.
- `-B/--collect-backups <EXTS>`: Probe backups (~,.bak,...). (Built-in list)
- `-g/--collect-words`: Build dynamic wordlist from responses.
- `-I/--dont-collect <EXTS>`: Ignore exts for collection.

**Output/Logging**:
- `-v/--verbosity <0-4>`: Log level. (0)
- `--silent`: URLs only.
- `-q/--quiet`: No banners/progress.
- `--json`: JSON output files.
- `-o/--output <FILE>`: Results file.
- `--debug-log <FILE>`: Debug logs.
- `--no-state`: Skip .state files.
- `--limit-bars <NUM>`: Max progress bars.

**Presets**:
- `--smart`: Auto-tune + collect words/backups.
- `--thorough`: --smart + exts + dir listings.

##### Advanced Features & New Stuff (2024-25)
- **Response Limiting**: `--response-size-limit 1048576` (1MB cap)—killer for APIs dumping gigs of data.
- **Dynamic Collection**: `--collect-words` now smarter, filters noise via regex in v2.12.
- **mTLS/Proxies**: SOCKS5h support beefed up; replay proxies for WAF bypass.
- **Recursion Tweaks**: `--force-recursion` ignores non-200s for deeper dives.

##### More Examples (Fresh Ones)
- API Fuzz with Size Limit: `feroxbuster -u https://api.example.com/v1 -w raft-medium-directories-lowercase.txt --methods GET,POST --data '{"q": "FUZZ"}' --response-size-limit 500k -o api.json --json`.
- Burp-Integrated Recursive: `feroxbuster -u http://target.local --burp -w common.txt -d 5 --collect-extensions -t 20 --rate-limit 5`.
- IPv6 + Custom Cert: `feroxbuster -u https://[2001:db8::1] --client-cert client.pem --client-key key.pem -w ipv6-dirs.txt -n -vv`.
- Dynamic Wordlist Build: `feroxbuster -u http://example.com --smart -w small.txt --collect-words --output dynamic.txt` (then reuse dynamic.txt for round 2).
- Time-Boxed Parallel: `echo "http://site1\nhttp://site2" | feroxbuster --stdin --parallel 2 --time-limit 15m -w subs.txt --add-slash`.

#### Gobuster (v3.8.2)
Go-based speed demon with modes galore. 2024-25 highlights: `--exclude-hostname-length` (auto-adjusts for long domains), `--force` (ignores precheck fails), Host header fuzzing in fuzz mode, wordlist offsets, and TFTP mode for old-school file grabs.

##### Installation (Updated)
- **Go (Req 1.24+)**: `go install github.com/OJ/gobuster/v3@latest`.
- **Binaries/Docker**: Releases page or `docker pull ghcr.io/oj/gobuster:3.8.2`.
- **Kali**: `sudo apt install gobuster` (v3.8.2 as of Aug '25).
- **Build**: `git clone https://github.com/OJ/gobuster.git && cd gobuster && go build`.

Verify: `gobuster version`.

##### All Command-Line Options (Full List, v3.8.2)
Global + mode-specific. New flags bolded.

**Core**:
- `-u <URL>`: Target.
- `-w <WORDLIST>`: Wordlist (req'd).
- `-x <EXTS>`: Extensions.
- `-t <THREADS>`: Concurrency. (Varies; 10 default dir)
- `-o <OUTPUT>`: File dump.
- `-q`: Quiet.
- `-l`: Show lengths.
- `-s <CODES>`: Status filter (ranges ok, e.g., 200-299).
- `-H <HDR>`: Headers.
- `-c <COOKIE>`: Cookies.
- `-a <UA>`: User-Agent.
- **`--delay <MS>`**: Req delay. (0)
- **`--timeout <S>`**: Timeout. (10)
- `--debug`: Debug logs (replaced -v).
- `--force`: Ignore prechecks (**new v3.8**).
- `--no-progress`: No bar.
- **`--offset <N>`**: Skip wordlist lines (**v3.6**).
- **`--retry <N>`**: Retry fails. (0)
- **`--retry-status <CODES>`**: Retry codes.
- `--proxy <URL>`: Proxy.
- `--insecure`: Skip TLS.
- `--add-slash`: Append /.
- `--expand`: Expand // in words.
- `--trim`: Trim whitespace.
- **`--url-encode`**: Encode payloads.
- **`--wildcard-forced`**: Force wildcard handling.
- `--no-fallback`: No 404 fallback.
- mTLS: `--client-cert/--client-key/--ca-cert`.
- Cookies: `--write-cookies/--cookie-jar`.

**New 2024-25**:
- **`--exclude-hostname-length`**: Auto-exclude based on hostname len (**v3.8**).
- **`--interface <IF>` / `--local-ip <IP>`**: Outgoing interface/IP (**v3.7**).
- **`--header-fuzzing`**: Fuzz headers (**v3.7**).
- Ranges in `-s`/`--blacklist` (**v3.5**).

**Modes** (Positional: `gobuster <mode> ...`):
- **dir**: Web dirs/files.
  - `--pattern <FILE>`: {GOBUSTER} patterns.
  - `--exclude-length <NS>`: Skip lengths.
- **dns**: Subdomains.
  - `-d/-do <DOMAIN>`: Domain.
  - `-r <RESOLVER>`: DNS server.
  - **`--no-fqdn`**: Skip search domains (**v3.6**).
  - `--wildcard`: Handle wildcards.
- **vhost**: Virtual hosts.
  - `--append-domain`: Add domain to words.
- **s3/gcs**: Buckets.
  - `--endpoint-url <URL>`: Custom endpoint (S3).
- **tftp**: TFTP files (**v3.4**).
  - `-s <SERVER>`: TFTP IP.
- **fuzz** (**v3.1+**): Param/header fuzz.
  - `-d <DATA>`: POST body.
  - `-A <METHOD>`: HTTP method.
  - Patterns with {GOBUSTER}.

##### Advanced Features & New Stuff (2024-25)
- **Host Fuzzing**: Probe vhosts via headers—game-changer for cloud.
- **Dynamic Exclusions**: `--exclude-hostname-length` adapts to long subdomains.
- **TFTP Mode**: Enum old IoT/legacy nets.
- **Patterns**: Complex fuzz like `/api/{GOBUSTER}?id={GOBUSTER}`.

##### More Examples (2025-Flavored)
- Host Fuzz (**new**): `gobuster fuzz -u https://example.com -H "Host: FUZZ.target.com" -w vhosts.txt -t 30 --insecure`.
- Offset Biglist: `gobuster dir -u http://target -w huge.txt --offset 5000 -x php -s 200 --exclude-length 0,123 -o clean.txt --force`.
- TFTP Enum (**v3.4**): `gobuster tftp -s 192.168.1.100 -w tftp-files.txt -t 10`.
- GCS Buckets: `gobuster gcs -w cloud-buckets.txt --no-progress -q`.
- Retry + Interface (**v3.7**): `gobuster dir -u https://api.site -w dirs.txt --interface wlan0 --local-ip 10.0.0.5 --retry 3 --retry-status 502,503 -t 50`.
- Fuzz Auth Header: `gobuster fuzz -u https://login.example.com -H "Authorization: Basic FUZZ" -w creds.txt --header-fuzzing`.

#### New Sections: Wordlist Recs, Pitfalls, Integrations, & Comparison

##### Top Wordlists (Tailored for 2025 Scans)
Use SecLists or Raft (github.com/projectdiscovery/public-bugbounty-programs). Start small, scale up.
| Type | Rec | Size | Why? |
|------|-----|------|------|
| Dirs | raft-medium-directories.txt | Med | Balanced for web apps. |
| Subs/DNS | subdomains-top1mil-5000.txt | Small | Fast vhost/DNS starts. |
| Files | common.txt (dirb) | Small | Quick file hunts. |
| APIs | api-endpoints.txt | Med | JSON-heavy, pair with --methods POST. |
| Backups | backups.txt | Tiny | .bak, ~, etc.—use --collect-backups. |
| Fuzz | raft-large-files.txt | Large | Deep param hunts; offset for subsets. |

Download: `git clone https://github.com/danielmiessler/SecLists.git`.

##### Common Pitfalls & Fixes
- **Rate Bans**: Start -t 10, --rate-limit 2; ramp up. Pitfall: Ignoring WAFs—use --random-agent + proxies.
- **False Positives**: Wildcards kill output. Fix: --dont-filter + manual baseline.
- **Huge Responses**: Ferox: --response-size-limit; Gob: --exclude-length.
- **Recursion Loops**: Ferox depth=2 initially; Gobuster lacks native—script loops.
- **TLS Snags**: --insecure for self-signed; mTLS for enterprise.
- **Wordlist Bloat**: Trim with `sed` or --offset; test on DVWA first.

##### Integrations (With SQLMap & Pals)
- **Post-SQLMap Recon**: After dumping DB schemas, bust /admin or /backup.php: `sqlmap ... --crawl=2` then pipe to Ferox: `sqlmap -u vuln --crawl=1 --batch | grep -o 'http[^ ]*' | feroxbuster --stdin --parallel 3 -w schema-dirs.txt`.
- **Chain with Nuclei**: `feroxbuster -u target --silent -o paths.txt && nuclei -l paths.txt -t cves/`.
- **Burp/ZAP**: Both support --burp proxy; Gob's --proxy for custom.
- **Scripted Pipeline** (Bash snippet):
  ```bash
  #!/bin/bash
  TARGET=$1
  gobuster dir -u $TARGET -w small.txt -o quick.txt -q
  feroxbuster -u $TARGET -w medium.txt --resume-from quick.state -o deep.txt --smart
  cat quick.txt deep.txt | sort -u > all_paths.txt
  sqlmap -u "$TARGET/all_paths.txt" --batch --dbs  # If SQLi suspected
  ```
- **Metasploit Tie-In**: Export Gob paths to msfconsole for auxiliary/scanner/http/dir_scanner.

##### Feroxbuster vs. Gobuster: Quick Comparison
| Aspect | Feroxbuster | Gobuster | Winner? |
|--------|-------------|----------|---------|
| **Speed** | Auto-tuned, Rust-fast | Go-blazing, multi-mode | Gob for raw speed |
| **Recursion** | Native, depth-controlled | None (manual chaining) | Ferox for deep dives |
| **Modes** | Web-only, recursive | Dir/DNS/VHost/S3/GCS/TFTP/Fuzz | Gob for versatility |
| **Filtering** | Regex/size/words/lines + auto-wildcard | Length/status + new hostname excl | Tie—Ferox more granular |
| **Collection** | Auto words/exts/backups | Patterns for fuzz | Ferox for dynamic |
| **Ease** | Presets (--smart) | Simple CLI | Gob for noobs |
| **New Hotness (2025)** | Response limits | Host fuzz + TFTP | Gob edges |

Bottom line: Ferox for recursive web crawls, Gob for quick multi-protocol blasts. Combo 'em for pentest gold.

### Concise Examples for Feroxbuster & Gobuster

Trimmed these down to essentials—quick commands with key flags, grouped by use case. Assumes v2.12 (Ferox) & v3.8.2 (Gob). Targets: `http://example.com`. Wordlists: Use SecLists (e.g., `common.txt`).

#### Feroxbuster (Recursive Web Buster)
- **Basic Dir Scan**: `feroxbuster -u http://example.com -w common.txt -o out.txt -t 20`
- **With Exts & Recursion**: `feroxbuster -u http://example.com -w dirs.txt -x php,js -d 3 --add-slash -o deep.txt`
- **Smart Auto-Tune**: `feroxbuster -u https://api.example.com --smart -w raft-medium.txt --rate-limit 5 -o smart.json --json`
- **Proxy/Burp + Filter**: `feroxbuster -u http://target --burp -s 200,301 -C 404 -vv -w small.txt`
- **POST Fuzz**: `feroxbuster -u http://example.com -m POST --data '{"user": "FUZZ"}' -w users.txt -o post.txt`
- **Resume + Limit**: `feroxbuster --resume-from ferox.state --time-limit 10m --threads 50`
- **API w/ Size Cap (New)**: `feroxbuster -u https://api.example.com -w endpoints.txt --response-size-limit 1M -q`

#### Gobuster (Multi-Mode Buster)
- **Dir Enum**: `gobuster dir -u http://example.com -w common.txt -x php -t 50 -o out.txt -s 200`
- **DNS Subs**: `gobuster dns -d example.com -w subs.txt -t 100 --wildcard -r 8.8.8.8`
- **VHost Probe**: `gobuster vhost -u https://example.com -w vhosts.txt --append-domain -s 200,301`
- **Fuzz Param**: `gobuster fuzz -u https://example.com/?id=FUZZ -w ids.txt -t 20 --url-encode`
- **POST Fuzz**: `gobuster fuzz -u https://login.example.com -w creds.txt -d 'user=FUZZ&pass=123' -H "Content-Type: application/x-www-form-urlencoded"`
- **S3 Buckets**: `gobuster s3 -w buckets.txt --endpoint-url https://s3.amazonaws.com -q`
- **Host Header Fuzz (New)**: `gobuster fuzz -u https://example.com -H "Host: FUZZ.example.com" -w subs.txt --insecure`
- **Retry + Offset**: `gobuster dir -u http://target -w huge.txt --offset 1000 --retry 3 --retry-status 500 -o retry.txt`

**Pro Tips**: Chain 'em—`gobuster dir ... -o paths.txt && feroxbuster -u http://example.com --stdin-from paths.txt --parallel 2`. Test on labs like DVWA. Need scripts for these? Holler.