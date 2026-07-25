# vulnhunter.sh

An intelligent, threaded, low-false-positive vulnerability **triage engine** for
bug bounty and VDP work. Feed it the URL lists you already collected with
`gau`, `gospider`, `hakrawler`, `katana`, or `waybackurls`, and it will:

1. **Normalize + deduplicate** them at the *template* level (same host + path +
   parameter names collapse to one representative — huge request savings on
   noisy wordlists).
2. **Classify** each parameter into the vulnerability classes it plausibly maps
   to (LFI / RFI / XSS / SQLi / CMDi), using curated `gf`/SecLists-style
   dictionaries.
3. **Actively validate** the candidates with a baseline-diff, multi-signal
   engine that is designed to confirm *true positives* and stay quiet on
   everything else.
4. Emit **JSON, CSV, HTML, Burp-XML and per-class Markdown** reports with
   copy-paste PoC URLs.

> ⚠️ **Authorization required.** Active mode sends real payloads, including
> time-based `sleep`/SQL-delay probes. Only run it against assets you own or a
> target explicitly in scope for a program you are authorized to test. You are
> responsible for your usage.

---

## Why the false-positive rate is low

Most param-fuzzers flag anything that "looks" reflected or errors once. This one
requires a **differential** signal — the vulnerability marker must appear in the
payload response **and be absent from a baseline response** — and for the
strongest verdicts it **re-confirms independently**:

| Verdict | Requirement |
|---------|-------------|
| `CONFIRMED` | signal present, absent from baseline, **and re-observed on a second request** |
| `HIGH` | signal present and absent from baseline (single observation) |
| `INFO` | weak/soft signal (e.g. HTML-encoded reflection) — only with `--reflections` |
| `OOB-CHECK` | payload delivered; needs you to confirm the out-of-band hit |

Per-class logic:

- **XSS** — injects a unique canary wrapped in `'"><canary>` and only reports
  when the angle brackets survive **unencoded** (real breakout). Encoded
  reflections are suppressed unless you pass `--reflections`.
- **SQLi** — three independent techniques: error-based (multi-DB error
  fingerprints that appear only after injection), boolean-based (length-ratio
  divergence between `1=1` and `1=2`), and time-based blind (statistical delay
  with baseline check + re-confirmation to defeat network jitter).
- **LFI** — requires the exact `root:...:0:0:` `/etc/passwd` signature, `win.ini`
  markers, `/proc/self/environ` env leak, or a decodable `php://filter` base64
  source — each checked against baseline.
- **CMDi** — time-based only, using 8 separator styles; requires a fast baseline
  plus two slow observations before reporting.
- **RFI/SSRF** — best confirmed out-of-band: pass `--collab <domain>` (Burp
  Collaborator / interactsh) and watch for the injected hostname. Without OOB it
  falls back to a `data://` wrapper code-exec canary.

**Validation result** (against a local test harness): 5/5 planted
vulnerabilities detected, 0 false positives against a hardened control server
that reflects everything HTML-encoded and never errors or sleeps.

---

## Requirements

Standard tools only: `bash` (>= 4), `curl`, `awk`, `sed`, `grep`, `sort`.
`jq` is optional (nicer JSON; a pure-bash fallback is used otherwise).
Runs on Linux and macOS. Temp files go to `/dev/shm` when available for speed
and to keep disk I/O and memory low.

```bash
chmod +x vulnhunter.sh
```

## Quick start

```bash
# 1) Passive triage — no requests, just classify + dedup a huge list (fast)
cat gau.txt gospider.txt | ./vulnhunter.sh -m passive -o triage

# 2) Active validation of everything, 30 threads
./vulnhunter.sh -l urls.txt -m active -t 30 -o run1

# 3) Only XSS + SQLi, routed through Burp, authenticated
./vulnhunter.sh -l urls.txt -m active -c xss,sqli \
    -x http://127.0.0.1:8080 -b 'session=abc' -H 'Authorization: Bearer X' -o run2

# 4) With out-of-band confirmation for RFI/SSRF
./vulnhunter.sh -l urls.txt -m active --collab xxxx.oastify.com -o run3

# 5) Resume an interrupted run (skips already-scanned URLs)
./vulnhunter.sh -l urls.txt -m active -o run1 --resume
```

## Options

```
-l FILE          Input URL list (repeatable). Also reads stdin.
-m MODE          passive | active                     (default: passive)
-c CLASSES       lfi,rfi,xss,sqli,cmdi                 (default: all)
-o DIR           Output directory                      (default: vulnhunter_<ts>)
-t N             Concurrent threads                    (default: 40)
--timeout SEC    Per-request timeout                   (default: 12)
--delay SEC      Delay between requests per worker     (default: 0)
--sleep SEC      Base delay for blind time-based checks (default: 6)
--retries N      Retries with exponential backoff      (default: 2)
--max-urls N     Cap number of targets                 (default: unlimited)
-H 'K: V'        Extra header (repeatable)
-b 'a=b; c=d'    Cookie string
-A 'UA'          Custom User-Agent
-x URL           Proxy (route via Burp/ZAP)
--collab DOMAIN  OOB domain for RFI/SSRF confirmation
--config FILE    Load key=value config (CLI overrides)
--resume         Skip URLs already scanned in the output dir
--robots         Respect robots.txt Disallow rules
--reflections    Also report HTML-encoded reflections as INFO (noisier)
-q               Quiet (findings only)
-h               Help
```

## Input formats

The normalizer greps `https?://…` tokens out of each line, so it accepts plain
URL lists, CSV/TSV with a URL column, JSON dumps from tools, and Burp-exported
URL lists without extra flags. Fragments (`#…`) and trailing punctuation are
stripped; only parameterized URLs proceed to testing.

## Output files

```
<outdir>/
  report.json             structured findings (jq-clean)
  report.csv              class,severity,url,param,evidence — import to trackers
  report.html             dark-theme visual report with severity chips
  report.burp.xml         Burp-style <issues> list
  lfi.md rfi.md xss.md sqli.md cmdi.md   per-class PoCs (Markdown)
  classified_targets.tsv  TAGS<TAB>URL — what was tested and why
  parameterized_urls.txt  deduplicated parameterized templates
  findings.tsv            raw records (REC<TAB>class<TAB>sev<TAB>url<TAB>param<TAB>evidence)
  scanned.txt             progress/resume ledger
```

### Example finding (JSON)

```json
{
  "class": "SQLI",
  "severity": "CONFIRMED",
  "url": "https://target/item?id=1",
  "param": "id",
  "evidence": "time-based blind (base 0.11s -> 6.05s/6.03s @ sleep 6s) | poc: https://target/item?id=1'%20AND%20SLEEP(6)--%20-"
}
```

## Performance & footprint

The design keeps memory flat regardless of list size:

- Input is streamed and deduplicated with `sort`/`awk`, never fully held in
  bash arrays.
- Each URL is validated by an **independent short-lived worker** fanned out with
  `xargs -P N`, so per-process memory stays small and there is no long-lived
  accumulator to leak — suitable for multi-day runs over very large lists.
- Template-level dedup typically removes the bulk of gau/wayback noise before a
  single request is sent.
- Class-targeted injection: a parameter is only probed for a class its **name**
  matches, cutting request volume dramatically versus spraying every payload at
  every parameter.

Tuning: raise `-t` for throughput; add `--delay`/lower `-t` to be gentle on
rate-limited targets; raise `--sleep` on noisy networks to make time-based
detection more robust (at the cost of speed).

## Notes, limits & honest caveats

- **GET-parameter focused.** It tests query-string injection points. POST/JSON/
  XML body injection, DOM XSS, mXSS, CSP analysis, and UNION column-counting are
  *not* performed here — those need a stateful browser or a full scanner
  (Burp/ZAP/dalfox). Use this to *triage* a large surface fast, then hand the
  confirmed/high hits to a deeper tool or manual testing.
- **RFI** realistically needs OOB; use `--collab`.
- Time-based checks are the most environment-sensitive; the baseline + double-
  confirmation logic suppresses most jitter FPs but very slow/unstable hosts can
  still cause misses (it deliberately errs toward *missing* rather than
  *false-alarming*).
- Payloads are read-only/benign (no `DROP`/`DELETE`/destructive commands).
- This is a triage aid, not a guarantee. Always manually verify before
  reporting to a program.

## Local self-test

```bash
# Confirms detection fires and stays quiet on a safe control server
bash selftest.sh
```


# vulnhunter

An intelligent, threaded, low-false-positive vulnerability **triage engine** for
bug bounty and VDP work. Ships in two equivalent implementations — pick whichever
fits your workflow; both share the same detection logic, CLI flags, and report
formats:

- **`vulnhunter.sh`** — pure bash (curl/awk/sed/grep, jq optional). No runtime
  to install; fans out with `xargs -P` for flat memory on huge lists.
- **`vulnhunter.py`** — stdlib-only Python 3.7+ (no `pip install` needed). Uses a
  `ThreadPoolExecutor`, streams the same JSON/CSV/HTML/Burp-XML/Markdown output.

Both were validated against the same harness: **5/5 planted vulns detected,
0 false positives** on a hardened control server.

```bash
# same flags either way
./vulnhunter.sh -l urls.txt -m active -t 30 -o run1
python3 vulnhunter.py -l urls.txt -m active -t 30 -o run1
```
 Feed it the URL lists you already collected with
`gau`, `gospider`, `hakrawler`, `katana`, or `waybackurls`, and it will:

1. **Normalize + deduplicate** them at the *template* level (same host + path +
   parameter names collapse to one representative — huge request savings on
   noisy wordlists).
2. **Classify** each parameter into the vulnerability classes it plausibly maps
   to (LFI / RFI / XSS / SQLi / CMDi), using curated `gf`/SecLists-style
   dictionaries.
3. **Actively validate** the candidates with a baseline-diff, multi-signal
   engine that is designed to confirm *true positives* and stay quiet on
   everything else.
4. Emit **JSON, CSV, HTML, Burp-XML and per-class Markdown** reports with
   copy-paste PoC URLs.

> ⚠️ **Authorization required.** Active mode sends real payloads, including
> time-based `sleep`/SQL-delay probes. Only run it against assets you own or a
> target explicitly in scope for a program you are authorized to test. You are
> responsible for your usage.

---

## Why the false-positive rate is low

Most param-fuzzers flag anything that "looks" reflected or errors once. This one
requires a **differential** signal — the vulnerability marker must appear in the
payload response **and be absent from a baseline response** — and for the
strongest verdicts it **re-confirms independently**:

| Verdict | Requirement |
|---------|-------------|
| `CONFIRMED` | signal present, absent from baseline, **and re-observed on a second request** |
| `HIGH` | signal present and absent from baseline (single observation) |
| `INFO` | weak/soft signal (e.g. HTML-encoded reflection) — only with `--reflections` |
| `OOB-CHECK` | payload delivered; needs you to confirm the out-of-band hit |

Per-class logic:

- **XSS** — injects a unique canary wrapped in `'"><canary>` and only reports
  when the angle brackets survive **unencoded** (real breakout). Encoded
  reflections are suppressed unless you pass `--reflections`.
- **SQLi** — three independent techniques: error-based (multi-DB error
  fingerprints that appear only after injection), boolean-based (length-ratio
  divergence between `1=1` and `1=2`), and time-based blind (statistical delay
  with baseline check + re-confirmation to defeat network jitter).
- **LFI** — requires the exact `root:...:0:0:` `/etc/passwd` signature, `win.ini`
  markers, `/proc/self/environ` env leak, or a decodable `php://filter` base64
  source — each checked against baseline.
- **CMDi** — time-based only, using 8 separator styles; requires a fast baseline
  plus two slow observations before reporting.
- **RFI/SSRF** — best confirmed out-of-band: pass `--collab <domain>` (Burp
  Collaborator / interactsh) and watch for the injected hostname. Without OOB it
  falls back to a `data://` wrapper code-exec canary.

**Validation result** (against a local test harness): 5/5 planted
vulnerabilities detected, 0 false positives against a hardened control server
that reflects everything HTML-encoded and never errors or sleeps.

---

## Requirements

Standard tools only: `bash` (>= 4), `curl`, `awk`, `sed`, `grep`, `sort`.
`jq` is optional (nicer JSON; a pure-bash fallback is used otherwise).
Runs on Linux and macOS. Temp files go to `/dev/shm` when available for speed
and to keep disk I/O and memory low.

```bash
chmod +x vulnhunter.sh
```

## Quick start

```bash
# 1) Passive triage — no requests, just classify + dedup a huge list (fast)
cat gau.txt gospider.txt | ./vulnhunter.sh -m passive -o triage

# 2) Active validation of everything, 30 threads
./vulnhunter.sh -l urls.txt -m active -t 30 -o run1

# 3) Only XSS + SQLi, routed through Burp, authenticated
./vulnhunter.sh -l urls.txt -m active -c xss,sqli \
    -x http://127.0.0.1:8080 -b 'session=abc' -H 'Authorization: Bearer X' -o run2

# 4) With out-of-band confirmation for RFI/SSRF
./vulnhunter.sh -l urls.txt -m active --collab xxxx.oastify.com -o run3

# 5) Resume an interrupted run (skips already-scanned URLs)
./vulnhunter.sh -l urls.txt -m active -o run1 --resume
```

## Options

```
-l FILE          Input URL list (repeatable). Also reads stdin.
-m MODE          passive | active                     (default: passive)
-c CLASSES       lfi,rfi,xss,sqli,cmdi                 (default: all)
-o DIR           Output directory                      (default: vulnhunter_<ts>)
-t N             Concurrent threads                    (default: 40)
--timeout SEC    Per-request timeout                   (default: 12)
--delay SEC      Delay between requests per worker     (default: 0)
--sleep SEC      Base delay for blind time-based checks (default: 6)
--retries N      Retries with exponential backoff      (default: 2)
--max-urls N     Cap number of targets                 (default: unlimited)
-H 'K: V'        Extra header (repeatable)
-b 'a=b; c=d'    Cookie string
-A 'UA'          Custom User-Agent
-x URL           Proxy (route via Burp/ZAP)
--collab DOMAIN  OOB domain for RFI/SSRF confirmation
--config FILE    Load key=value config (CLI overrides)
--resume         Skip URLs already scanned in the output dir
--robots         Respect robots.txt Disallow rules
--reflections    Also report HTML-encoded reflections as INFO (noisier)
-q               Quiet (findings only)
-h               Help
```

## Input formats

The normalizer greps `https?://…` tokens out of each line, so it accepts plain
URL lists, CSV/TSV with a URL column, JSON dumps from tools, and Burp-exported
URL lists without extra flags. Fragments (`#…`) and trailing punctuation are
stripped; only parameterized URLs proceed to testing.

## Output files

```
<outdir>/
  report.json             structured findings (jq-clean)
  report.csv              class,severity,url,param,evidence — import to trackers
  report.html             dark-theme visual report with severity chips
  report.burp.xml         Burp-style <issues> list
  lfi.md rfi.md xss.md sqli.md cmdi.md   per-class PoCs (Markdown)
  classified_targets.tsv  TAGS<TAB>URL — what was tested and why
  parameterized_urls.txt  deduplicated parameterized templates
  findings.tsv            raw records (REC<TAB>class<TAB>sev<TAB>url<TAB>param<TAB>evidence)
  scanned.txt             progress/resume ledger
```

### Example finding (JSON)

```json
{
  "class": "SQLI",
  "severity": "CONFIRMED",
  "url": "https://target/item?id=1",
  "param": "id",
  "evidence": "time-based blind (base 0.11s -> 6.05s/6.03s @ sleep 6s) | poc: https://target/item?id=1'%20AND%20SLEEP(6)--%20-"
}
```

## Performance & footprint

The design keeps memory flat regardless of list size:

- Input is streamed and deduplicated with `sort`/`awk`, never fully held in
  bash arrays.
- Each URL is validated by an **independent short-lived worker** fanned out with
  `xargs -P N`, so per-process memory stays small and there is no long-lived
  accumulator to leak — suitable for multi-day runs over very large lists.
- Template-level dedup typically removes the bulk of gau/wayback noise before a
  single request is sent.
- Class-targeted injection: a parameter is only probed for a class its **name**
  matches, cutting request volume dramatically versus spraying every payload at
  every parameter.

Tuning: raise `-t` for throughput; add `--delay`/lower `-t` to be gentle on
rate-limited targets; raise `--sleep` on noisy networks to make time-based
detection more robust (at the cost of speed).

## Notes, limits & honest caveats

- **GET-parameter focused.** It tests query-string injection points. POST/JSON/
  XML body injection, DOM XSS, mXSS, CSP analysis, and UNION column-counting are
  *not* performed here — those need a stateful browser or a full scanner
  (Burp/ZAP/dalfox). Use this to *triage* a large surface fast, then hand the
  confirmed/high hits to a deeper tool or manual testing.
- **RFI** realistically needs OOB; use `--collab`.
- Time-based checks are the most environment-sensitive; the baseline + double-
  confirmation logic suppresses most jitter FPs but very slow/unstable hosts can
  still cause misses (it deliberately errs toward *missing* rather than
  *false-alarming*).
- Payloads are read-only/benign (no `DROP`/`DELETE`/destructive commands).
- This is a triage aid, not a guarantee. Always manually verify before
  reporting to a program.

## Local self-test

```bash
# Confirms detection fires and stays quiet on a safe control server
bash selftest.sh
```
python3 vulnhunter.py -l urls.txt -m active -c xss,sqli -t 30 -x http://127.0.0.1:8080 -o run1
cat gau.txt | python3 vulnhunter.py -m passive -o triage
