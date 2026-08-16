# Cyber Attack Detection and Defense System

A modular, host-based Intrusion Detection and Defense System built from scratch in Python — designed to be understandable line-by-line, explainable in interviews, and extensible like a real software product, not a one-off script collection.

---

## Project Philosophy

Every feature followed the same workflow: design the architecture, design the data structures, implement, test, explain every line, commit. Priorities throughout: readability, modularity, separation of concerns, and extensibility over the shortest possible code.

---

## Project Status

| Phase | Status |
|---|---|
| Phase 1 — Packet Analysis | ✅ Complete |
| Phase 2 — Intrusion Detection | ✅ Complete |
| Phase 3 — Firewall Defense Engine | ✅ Complete |
| Phase 4 — Phishing Detection | ✅ Complete |
| Phase 5 — Malware Detection | ✅ Complete |
| Final Phase — Dashboard | Not started |

---

## Architecture Overview

```
Traffic
  ↓
live_monitoring.py (packet capture, multi-interface)
  ↓
  ├── ThreatDetector (analyzer/detector.py)       → Phase 2 network attack detection
  ├── FirewallManager (firewall/firewall_manager.py) → Phase 3 automated + reviewed defense
  └── MalwareDetector (malware/malware_detector.py)  → Phase 5 DNS/beaconing/blacklist detection

PhishingDetector (phishing/phishing_detector.py) → Phase 4, standalone URL analysis
```

Each phase is a self-contained package with its own coordinator class, mirroring the same pattern throughout: one file per responsibility, a thin coordinator that delegates rather than implements, and every detection unit returning a predictable, side-effect-free result.

---

## Folder Structure

```
CyberAttackDetection/
    analyzer/
        detector.py              — Phase 2 coordinator
        statistics.py
        host_tracker.py
        packet_reader.py
        live_monitoring.py       — live capture entry point, wires all phases together
        attacks/
            port_scan.py
            syn_flood.py
            icmp_flood.py
            udp_flood.py
            ssh_bruteforce.py
    firewall/
        rule_generator.py        — iptables wrapper, real-state verification
        whitelist.py             — persistent, protects trusted IPs
        blacklist.py             — persistent, always-block IPs
        pending_review.py        — persistent, non-blocking manual-review queue
        firewall_manager.py      — Phase 3 coordinator
        review.py                — manual CLI tool for blocking/unblocking
        setup_whitelist.py       — one-time safe-IP seeding script
    phishing/
        url_analyzer.py          — structural URL checks (IP host, @ symbol, subdomains, length)
        keyword_detector.py      — scaled suspicious-keyword scoring
        typosquatting_detector.py — edit-distance brand impersonation detection
        ssl_validator.py         — live certificate validation
        risk_scorer.py           — score-to-risk-level mapping
        phishing_detector.py     — Phase 4 coordinator, includes trusted-domain score reduction
        data/
            top_domains.csv      — Tranco top-10k domain list
    malware/
        dns_anomaly_detector.py  — entropy + vowel-ratio DGA detection, known-domain bypass
        connection_tracker.py    — DNS query volume/diversity, time-windowed
        beaconing_detector.py    — timing-regularity detection via coefficient of variation
        c2_blacklist.py          — persistent known-bad IP/domain list
        malware_detector.py      — Phase 5 coordinator
    captures/
    README.md
    requirements.txt
    .gitignore
```

---

## Phase 2 — Intrusion Detection

Five independent detectors, each following the same interface: `detect(...)` → `True`/`False`, no printing, no side effects.

| Detector | Signal | Data structure | Threshold |
|---|---|---|---|
| Port Scan | Unique destination ports per source IP | `defaultdict(set)` | 10 unique ports |
| SYN Flood | Total SYN packets per source IP | `Counter` | 100 |
| ICMP Flood | Total echo *requests* per source IP (type 8 only) | `Counter` | 50 |
| UDP Flood | Total UDP packets per source IP | `Counter` | 100 |
| SSH Brute Force | SYN packets to port 22 per source IP | `Counter` | 5 |

**Real bugs found and fixed during testing:**
- **UDP port-scan false positive** — target's replies to a scan were being counted as the target itself scanning back. Fixed by tracking probe direction (`seen_probes`) so only genuine outbound probes count.
- **ICMP flood false positive** — target's echo *replies* were counted toward the flood total. Fixed by checking ICMP type (`type == 8`, echo request only).

---

## Phase 3 — Firewall Defense Engine

`FirewallManager` coordinates decisions; `RuleGenerator` executes real `iptables` commands.

**Decision flow per alert:** already-blocked → whitelisted → blacklisted → auto-block (floods) → manual-review (port scan, SSH brute force).

- **Floods** are auto-blocked immediately — low false-positive risk, no legitimate reason for that volume.
- **Port scan / SSH brute force** are queued to a persistent `pending_review.json`, never block live monitoring with an interactive prompt (a live IDS must never stall waiting on a human decision while an attacker is mid-scan).
- **Whitelist and blacklist are both persisted to JSON**, not held in memory — critical, since an in-memory-only design was found to silently fail across separate script runs.
- `review.py` is a standalone CLI tool to inspect and act on both currently-blocked IPs (verified live against real iptables state) and pending-review IPs.

**Real bug found and fixed:** `RuleGenerator` originally tracked blocked IPs in an in-memory Python `set`, which meant `unblock_ip()` silently failed when run as a separate process from `block_ip()`, since the set started empty each time. Fixed by checking real iptables state directly (`iptables -C`) instead of trusting memory.

**Scope note:** this is a host-based firewall — `iptables` rules only protect the machine running `live_monitoring.py`, not other devices on the network.

---

## Phase 4 — Phishing Detection

Four independent scoring modules, each returning `(score, reasons)`, combined by `RiskScorer` into a LOW/MEDIUM/HIGH verdict.

| Module | Checks | Points |
|---|---|---|
| URL Analyzer | Raw IP host (+25), `@` symbol (+25), excessive subdomains (+15), long URL (+10) |
| Keyword Detector | Suspicious keywords, scaled per match, capped at +40 total |
| Typosquatting Detector | Edit-distance ≤2 from a known brand (Tranco top-10k list) (+30) |
| SSL Validator | No HTTPS (+20), invalid/expired/self-signed certificate (+20) |

**Trusted-domain score reduction:** if a URL's hostname is an exact match or subdomain of a known trusted brand *and* has valid SSL, the total score is multiplied by 0.2 — addressing the real false-positive case where legitimate sites (e.g. `accounts.google.com/signin`) score high purely from normal authentication-related keywords.

**Typosquatting uses edit distance (Levenshtein distance)**, implemented via dynamic programming — a genuinely different algorithmic technique from the counting/set-based logic in Phase 2, worth noting as a distinct skill demonstrated in this project. A length-based pre-filter avoids running the expensive comparison against all 10,000 domains for every URL.

**Known limitation:** legitimate but less-famous domains (not in the top-10k list) receive no trust reduction and may score higher than they should — a real, honest trade-off of using a fixed popularity list rather than a live reputation API.

---

## Phase 5 — Malware Detection

Four modules addressing malware's tendency to *evade* volume-based detection by staying quiet and blending in.

| Module | Technique | Signal |
|---|---|---|
| DNS Anomaly Detector | Shannon entropy (normalized) + vowel-ratio analysis | Randomly-generated (DGA-style) domain names |
| Connection Tracker | `defaultdict(set)` with a sliding time window | Unusually high count of distinct domains queried in a short window |
| Beaconing Detector | Coefficient of variation (std dev / mean) of connection time gaps | Statistically regular "check-in" timing, characteristic of C2 communication |
| C2 Blacklist | Persistent known-bad IP/domain list | Direct match against known malicious infrastructure |

**Beaconing detection is the most advanced module in the project** — it tracks a rolling window of connection timestamps per `(source_ip, destination_ip)` pair and uses real time-series statistics (not simple counting) to detect automated, machine-regular check-in patterns that a human browsing normally wouldn't produce. It exposes both a one-time alert (`record_connection`) and a live status check (`is_currently_beaconing`, `get_all_active_beacons`) — a deliberate design decision separating "was this ever flagged" from "is this happening right now," since ongoing malware communication shouldn't go silent after a single alert.

**Real bug found and fixed:** `DNSAnomalyDetector`'s first version used raw (non-normalized) entropy against a fixed threshold, which unfairly penalized longer strings and let some real words with mostly-unique letters (`facebook.com`, entropy 0.98 normalized) score dangerously close to flagged. Fixed by (1) normalizing entropy against the theoretical maximum for a given string's length, and (2) adding a second, independent vowel-ratio signal, since neither check alone reliably distinguishes "random" from "coincidentally low-repetition real word."

**Honest limitation:** entropy and vowel-ratio checks only catch crude, character-random DGA domains. Syllable-based or dictionary-based DGA techniques (which generate pronounceable fake words or concatenate real words) would evade both checks entirely — a known, documented gap that mirrors real-world DGA detection challenges, where production systems typically add ML classification and NXDOMAIN-rate tracking as additional layers.

---

## Cross-Phase Design Patterns

**Consistent detector interface.** Every unit — from `PortScanDetector.detect()` in Phase 2 to `URLAnalyzer.analyze()` in Phase 4 — returns a predictable value and never prints, logs, or has side effects. This is what allows coordinators (`ThreatDetector`, `PhishingDetector`, `MalwareDetector`) to treat every module interchangeably via a loop instead of repetitive per-module code.

**Persistent state where correctness demands it.** Whitelist, blacklist, pending-review, and C2 blacklist are all JSON-backed, not in-memory — a direct response to a real bug (Phase 3's `RuleGenerator`) caused by trusting memory that doesn't survive across separate script executions.

**Alert-once, not alert-repeatedly.** Every detector tracks an `alerted` set (or equivalent) to avoid re-firing on every packet after a threshold is crossed once — solved once in Phase 2 and reused as a standing pattern throughout.

**Sibling-package imports.** `analyzer/`, `firewall/`, `phishing/`, and `malware/` are siblings, not nested. Every entry-point file adds its own parent directory to `sys.path` at runtime, so any file can be run directly regardless of the current working directory, without requiring `-m` module syntax or a fixed folder location.

---

## Known Limitations (Project-Wide)

1. **No time-window reset in Phase 2 detectors.** `SynFloodDetector`, `ICMPFloodDetector`, `UDPFloodDetector`, and `SSHBruteForceDetector` accumulate counts for the lifetime of the process, with no decay. `ConnectionTracker` (Phase 5) demonstrates the fix pattern (sliding time window) but it hasn't been retrofitted into the Phase 2 detectors yet.
2. **Host-based scope only.** All firewall actions protect only the machine running `live_monitoring.py`.
3. **Phase 4 typosquatting/trust logic depends on a static top-10k domain list** — legitimate but obscure sites get no benefit of the doubt; a live reputation API (e.g. Google Safe Browsing) would close this gap but was deliberately not used, to keep the detection logic self-built and interview-explainable rather than delegated to a third-party black box.
4. **Phase 5 DNS anomaly detection only catches crude, character-random DGA domains** — syllable-based and dictionary-based DGA techniques are not detected by the current entropy/vowel-ratio checks.
5. **Pending-review entries are not automatically cleared** if the same IP is later auto-blocked by a different Phase 2 detector firing on the same traffic burst — cosmetic redundancy in `review.py` output, not a functional bug.

---

## Testing Environment

- **Two-VM lab setup**: a monitoring Kali VM (own IP whitelisted) and a separate, cloned attacker Kali VM, both on a VirtualBox Host-Only/Internal Network — ensures alert source IPs reflect genuine external traffic rather than the monitor's own whitelisted IP.
- **Cloning requires**: regenerating MAC address, `/etc/machine-id`, and SSH host keys, or the clone can behave like "the same machine" on the network.
- **Resource caution**: uncontrolled flood tools (`hping3 --flood`) can crash a resource-limited VM — always use rate-limited flags (`-i u10000 -c <count>`) instead.
- **Loopback traffic** (e.g. testing SSH brute force against the monitor's own machine) requires explicitly capturing the `lo` interface, since same-machine traffic doesn't route through the physical NIC.

---

## What's Next

- **Final Phase — Dashboard**: live monitoring view, alert history, statistics, threat scoring, blocked-IP list, and reports, unifying all five phases into one interface.
- Optional hardening: retrofit sliding-time-window logic (proven in Phase 5) into Phase 2's flood detectors; auto-clear pending-review entries on redundant auto-block.
