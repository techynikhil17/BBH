# Bug Bounty Research Pipeline

An AI-driven, knowledge-compounding research system for authorized bug bounty security research. The system ingests publicly disclosed vulnerability reports, extracts patterns from them, generates structured skill files, and uses those skills to guide live research sessions — automatically updating the skill library after every session so knowledge accumulates over time.

Built for use with Claude Code. No Anthropic SDK, no API keys required.

---

## What This Is

Most bug bounty research is ephemeral: a researcher investigates a target, finds (or misses) a bug, and moves on with no persistent record of what was tried and why it did or didn't work. This system treats research as a compounding knowledge base instead.

Every session feeds back into the skill library:
- Successful findings get documented with full attack chains
- Failed approaches are logged so they aren't repeated
- Novel patterns get flagged for promotion into new skills
- Confirmed chains between vulnerability classes get recorded in a persistent graph

The result is a library that gets sharper every session, not one that resets each time.

---

## System Architecture

The pipeline has six stages. Stages 1 is automated Python. Stages 2–6 use Claude Code as the reasoning engine via a task-file handoff pattern (Python writes a task file to `data/claude_tasks/pending/`; Claude Code processes it and writes a response to `data/claude_tasks/completed/`; Python reads and applies the result).

```
Stage 1: Collector    — scrapes 500+ disclosed reports from HackerOne, GitHub, Medium
Stage 2: Extractor    — extracts vulnerability patterns from raw report text
Stage 3: Generator    — synthesizes patterns into structured skill.md files
Stage 4: Researcher   — interactive research sessions using skills as hypotheses
Stage 5: Updater      — post-session skill synthesis, pattern promotion, backups
Stage 6: Reporter     — generates program-ready bug bounty submissions
```

Plus a supporting `recon/` module that produces target intelligence before any session, and an `orchestrator/` that ties all components together with scope enforcement.

State is persisted in SQLite. There are no API calls to Anthropic; Claude Code provides all reasoning via the task-file handoff. Scope is enforced in three independent places (orchestrator, recon filter, researcher validator) so no component can accidentally operate on an out-of-scope target.

---

## Repository Structure

```
Bug-Bounty/
├── collector/          # Stage 1: report scraping (HackerOne, GitHub, Medium)
├── extractor/          # Stage 2: pattern extraction from raw reports
├── generator/          # Stage 3: skill.md generation from patterns
├── researcher/         # Stage 4: interactive research session management
├── updater/            # Stage 5: post-session skill updates and backups
├── reporter/           # Stage 6: bug bounty report generation
├── recon/              # Recon pipeline (subdomains, live services, tech stack, URLs)
├── orchestrator/       # Master CLI: scope enforcement, pipeline coordination, dashboard
├── skills/             # Skill library (24 skills across 12 vulnerability categories)
├── saml-research/      # Deep SAML/ruby-saml research documentation
├── data/
│   ├── claude_tasks/   # Task queue: pending/ (Python writes) + completed/ (Claude writes)
│   ├── patterns/       # Extracted patterns (JSONL + SQLite)
│   ├── raw/            # Collected reports (JSONL)
│   ├── recon/          # Recon output per target (JSON)
│   ├── sessions/       # Session state and active scope
│   ├── reports/        # Generated bug bounty reports
│   └── logs/           # Per-component logs
├── scripts/            # Diagnostic utilities
├── tests/              # Pytest test suite
├── scope.json          # Target program scope (in-scope / out-of-scope assets)
├── CLAUDE.md           # Full system documentation, hard rules, CLI reference
└── setup_env.sh        # Recon tool installer (Go binaries)
```

---

## Prerequisites

**Python dependencies:**
```bash
pip install -r requirements.txt
```
Key packages: `playwright`, `pydantic`, `rich`, `click`, `pytest`, `aiohttp`

**Recon tools (Go binaries):**
```bash
bash setup_env.sh
```
Installs: `subfinder`, `assetfinder`, `httpx`, `nuclei`, `gau`, `waybackurls`

---

## Quick Start — Full Pipeline

```bash
# 1. Load scope (mandatory first step)
python -m orchestrator.main load-scope --program shopify --file scope.json

# 2. Collect disclosed reports
python -m collector.main collect --sources all --limit 500

# 3. Extract vulnerability patterns (writes tasks for Claude Code)
python -m extractor.main extract --input data/raw/reports.jsonl
python -m extractor.main process-tasks     # Claude Code processes these

# 4. Generate skill files (writes tasks for Claude Code)
python -m generator.main generate --input data/patterns/patterns.jsonl --output skills/
python -m generator.main process-tasks     # Claude Code synthesizes skills
python -m generator.main index --skills-dir skills/

# 5. Run recon on target
python -m orchestrator.main recon --target api.shopify.com

# 6. Select skill (Claude Code reads brief and recommends)
python -m orchestrator.main select-skill --recon data/recon/api.shopify.com.json

# 7. Start research session
python -m researcher.main start \
  --program shopify \
  --target api.shopify.com \
  --scope scope.json \
  --skill sqli/auth-bypass-via-sqli \
  --recon data/recon/api.shopify.com.json

# 8. End session when complete
python -m researcher.main end --session-id <session_id>

# 9. Update skill files from session (mandatory)
python -m updater.main update \
  --session data/sessions/<session_id>/result.json \
  --skills-dir skills/
python -m updater.main process-tasks       # if synthesis tasks were generated

# 10. Generate bug bounty report
python -m reporter.main generate-all \
  --session data/sessions/<session_id>/result.json \
  --platform hackerone \
  --output data/reports/
python -m reporter.main process-tasks      # Claude Code writes report narrative

# 11. Review before submitting (always)
python -m reporter.main review --report data/reports/<report_file>
```

---

## Component Reference

### Collector
Scrapes publicly disclosed bug bounty reports. Active sources: HackerOne disclosed reports, GitHub security writeups, Medium RSS feeds. BugCrowd and Pentesterland are deprecated sources kept for reference.

```bash
python -m collector.main collect --sources all --limit 500
python -m collector.main collect --sources hackerone --sources github
python -m collector.main stats
```

Reports are stored deduplicated in SQLite and written to `data/raw/reports.jsonl`.

---

### Extractor
Reads raw report text and extracts structured vulnerability patterns: attack class, affected component, behavioral signal, stack hints, severity, novelty flag. Patterns that don't match anything in the existing skill library are flagged for promotion.

```bash
python -m extractor.main extract --input data/raw/reports.jsonl
python -m extractor.main process-tasks
python -m extractor.main stats
python -m extractor.main review-novel
```

Claude Code processes `extraction` task files written to `data/claude_tasks/pending/` and writes structured JSON patterns to `data/claude_tasks/completed/`.

---

### Generator
Groups patterns by vulnerability class and synthesizes them into `skill.md` files. Each skill gets a testing workflow, detection signals, chain opportunities, and an assumptions-to-challenge section derived from the pattern set.

```bash
python -m generator.main generate --input data/patterns/patterns.jsonl --output skills/
python -m generator.main process-tasks
python -m generator.main validate --skills-dir skills/
python -m generator.main index --skills-dir skills/    # regenerates skills/README.md
```

---

### Researcher
The interactive research session manager. Displays a research brief combining the skill file, recon data, and prior session history. Tracks every probe, observation, and chain hypothesis. Updates skill file sections in real-time when novel signals are found.

```bash
python -m researcher.main start --program <p> --target <t> --scope scope.json --skill <s> --recon <r>
python -m researcher.main resume --session-id <id>
python -m researcher.main end --session-id <id>
python -m researcher.main graph             # inspect chain knowledge graph
python -m researcher.main summary --session-id <id>
```

Session state persists in SQLite. The chain knowledge graph (what vulnerabilities combine with what) is saved to `researcher/knowledge/chain_graph.json` and grows across all sessions.

---

### Updater
Post-session synthesis. Compares session findings against existing skill content, promotes frequently-seen patterns, extends chain graph, and backs up every skill before writing. Use `history` and `restore` to manage backups.

```bash
python -m updater.main update --session data/sessions/<id>/result.json --skills-dir skills/
python -m updater.main process-tasks
python -m updater.main history --skill auth/saml-aml-bypass
python -m updater.main restore --skill auth/saml-aml-bypass --timestamp 20260528_143022
python -m updater.main pending-promotion    # patterns seen once, needing one more session
```

Running the updater after every session is mandatory — it is the mechanism that makes the system compound over time.

---

### Reporter
Generates program-ready bug bounty reports from confirmed session findings. Handles CVSS 3.1 scoring, impact chain escalation, and multi-platform formatting (HackerOne, BugCrowd, generic). Claude Code writes the narrative sections.

```bash
python -m reporter.main generate-all --session data/sessions/<id>/result.json --platform hackerone --output data/reports/
python -m reporter.main process-tasks
python -m reporter.main generate --session <path> --finding <id> --platform hackerone
python -m reporter.main generate-chain --session <path> --chain-id <id>
python -m reporter.main review --report <path>
python -m reporter.main list --session <path>
```

Always run `review` before submitting. The reviewer checks for missing PoC, CVSS consistency, and scope validity.

---

### Recon
Automated target intelligence. Discovers subdomains, identifies live services via httpx, fingerprints tech stacks, harvests historical URLs via gau/waybackurls, runs nuclei templates for known CVEs. All results are scope-filtered and written to `data/recon/<target>.json`.

```bash
python -m recon.main run --target shopify.com --scope scope.json
python -m recon.main run --target shopify.com --quick   # skips nuclei + history
python -m recon.main show --input data/recon/shopify.com.json
python -m recon.main list --recon-dir data/recon/
```

Never select a skill before running recon. Skill selection without target intelligence is guessing.

---

### Orchestrator
The master CLI. Loads scope, coordinates all components, shows the system dashboard, and routes pending Claude Code tasks. Start every session here.

```bash
python -m orchestrator.main load-scope --program shopify --file scope.json
python -m orchestrator.main scope                    # show active scope
python -m orchestrator.main recon --target <t>
python -m orchestrator.main select-skill --recon <path>
python -m orchestrator.main tasks                    # show all pending Claude Code tasks
python -m orchestrator.main status                   # live dashboard
python -m orchestrator.main chains                   # chain knowledge graph
python -m orchestrator.main sessions                 # list past sessions
python -m orchestrator.main full-pipeline --program shopify --scope scope.json
```

---

## Scope Configuration

All research is gated by `scope.json`. Load it before doing anything else. The orchestrator, recon module, and researcher each independently validate scope — no component can test an out-of-scope target.

The included `scope.json` is configured for Shopify as an example (HackerOne program). Replace with your actual target program's scope before running sessions.

```json
{
  "program": "your-program",
  "platform": "hackerone",
  "in_scope": [
    { "asset": "*.example.com", "type": "URL", "environment": "core" }
  ],
  "out_of_scope": [
    { "asset": "status.example.com", "reason": "monitoring only" }
  ]
}
```

```bash
python -m orchestrator.main load-scope --program your-program --file scope.json
```

---

## The Skill Library

The `skills/` directory contains the core knowledge base — 22 skills (plus the SAML skill not in the auto-index) across 12 vulnerability categories. Each skill is a `skill.md` file generated from real disclosed reports.

### Skill Structure

Every skill contains the same sections:

| Section | Purpose |
|---|---|
| **OVERVIEW** | Root cause, what developers miss, attacker impact |
| **PRECONDITIONS** | Go/no-go checklist — fewer than 2 confirmed = deprioritize |
| **DETECTION METHODOLOGY** | Phase 1 (surface discovery), Phase 2 (active probing), Phase 3 (confirmation) |
| **TESTING WORKFLOW** | Step-by-step probe sequence |
| **COMMON PATTERNS** | Real-report frequency table: signal, stack hints, feature type |
| **VULNERABLE CODE PATTERNS** | Greppable code shapes with bug explanation |
| **DETECTION SIGNALS** | Positive, negative, escalation signals |
| **CHAIN OPPORTUNITIES** | What this chains with + combined impact + confidence |
| **ASSUMPTIONS TO CHALLENGE** | Developer misconceptions to test — this is where novel bugs live |
| **FAILED APPROACHES** | Dead-end probes from prior sessions — don't repeat these |
| **ATTACK CHAINS DISCOVERED** | Confirmed multi-step chains with preconditions and impact |
| **NOVEL DISCOVERIES LOG** | Session-by-session research diary |
| **SCOPE CHECKLIST** | Mandatory pre-test verification |
| **REPORTING TEMPLATE HINTS** | CVSS, impact statement, remediation, PoC format |

### Current Skill Inventory

| Category | Skill | Severity | Typical Payout |
|---|---|---|---|
| **auth** | saml-aml-bypass | critical | $5,000–$50,000+ |
| **auth_bypass** | 2fa-state-overwrite | high | — |
| **business_logic** | client-side-feature-gating | high | ~$3,000 |
| **business_logic** | uncaught-exception-in-tls-callback | high | — |
| **command_injection** | config-injection-via-resource-spec-path | high | — |
| **idor** | missing-authorization-on-import-upload | high | — |
| **info_disclosure** | firebase-credentials-in-client-bundle | critical | — |
| **info_disclosure** | post-logout-cached-data | low | — |
| **info_disclosure** | shared-mutable-state-leaks-session-cookie-across-loads | high | — |
| **info_disclosure** | unauthenticated-static-file-exposure | high | — |
| **info_disclosure** | uninitialized-buffer-leakage-under-timing-race | high | — |
| **prototype_pollution** | header-name-as-prototype-key-causes-uncaught-typeerror | high | — |
| **sqli** | auth-bypass-via-sqli | critical | — |
| **sqli** | blind-or-error-based-on-corporate-endpoint | critical | — |
| **sqli** | error-and-time-based-blind-on-theme-selector | critical | — |
| **sqli** | unauthenticated-post-without-csrf | critical | — |
| **ssrf** | ipv6-nat64-allowlist-bypass | high | — |
| **ssti** | asp-net-template-parser-injection | critical | — |
| **subdomain_takeover** | dangling-dns-on-corporate-domain | high | — |
| **xss** | dom-xss-via-import-filename-preview | high | ~$500 |
| **xss** | reflected | medium | — |
| **xss** | self-xss-elevated-via-cookie-tossing-and-csrf-prediction | high | — |
| **xss** | stored-xss-in-isolation-email-field-feeds-auth-approval | high | — |

The auto-generated index at `skills/README.md` lists all skills with chain opportunity counts. Regenerate it with `python -m generator.main index`.

### Most Common Chain Targets

Based on chain opportunities documented across all skills:

| Chain To | Skills Referencing | Why It Matters |
|---|---|---|
| auth_bypass | 12 | Most vulns escalate to auth if you can combine |
| info_disclosure | 11 | Intermediate step in nearly every chain |
| rce | 6 | Ultimate escalation target |
| csrf | 5 | Amplifies nearly any write-access bug |
| idor | 3 | Combined with auth bugs for full account access |

---

## SAML Research

The `saml-research/` directory contains deep research documentation for GitLab's SAML authentication stack, targeting ruby-saml (version 1.18.x) and its interaction with Nokogiri/libxml2 and REXML.

### Files

**`RESEARCH_CONTEXT.md`** — Full attack surface map for the GitLab/ruby-saml SAML stack. Covers:
- Architecture (GitLab Rails → omniauth-saml → ruby-saml → Nokogiri → REXML)
- 6 known exploited parser differential CVEs (CVE-2025-25291/25292, CVE-2025-23369, CVE-2025-66568, CVE-2024-45409, CVE-2024-9487)
- XSW attack surface and spec-level logic bugs
- GitLab-specific code paths (auth_hash layer, group attribute injection, NameID normalization)
- Research questions prioritized by likelihood of yielding new bugs
- Signature sources that require no credentials (WS-Federation metadata, SAML metadata endpoint)

**`EXPLOIT_ATTEMPTS_LOG.md`** — Complete research diary of every attack attempted, including:
- 15 attack attempts with full hypothesis, what was found, outcome, and exact failure reason
- 3 real bugs found: SLO POST-binding fail-open (forced logout), XMLEnc CBC oracle chain, InResponseTo not checked by default
- Dead ends: void canonicalization (REXML crash, SignedInfo cascade, signature location mismatch), classic XSW (blocked by validate_signed_elements), REXML XXE (structurally impossible), entity expansion DoS (strict zero in REXML 3.4.x)
- Parser differential data flow analysis — full variable-by-variable mapping of REXML vs Nokogiri paths through cache_referenced_xml
- 7 unexplored research directions for future sessions

The SAML skill (`skills/auth/saml-aml-bypass/skill.md`) is the most developed skill in the library at 510 lines, containing 12 vulnerable code patterns, 13 ruby-saml-specific findings (F1–F13) with code locations, spec-mandated validation checklist (S1–S12), 13 named attack chains (V1–V13), and 3 confirmed real chains (C1–C3).

---

## Hard Rules

These rules are encoded in `CLAUDE.md` and enforced in the system. They cannot be overridden by any instruction.

1. **Scope gate** — `scope.json` must be loaded and validated before any testing discussion. If a target is out of scope: stop, do not proceed.

2. **Recon before skill selection** — Never recommend which skill to test without recon data. Skill selection without a target intelligence snapshot is guessing.

3. **Skill file first** — Read the full skill.md before proposing any tests. Novel hypotheses are encouraged, but only after reading the skill file. Never repeat approaches listed in FAILED APPROACHES.

4. **Log everything before session end** — Every observation, failed approach, and chain hypothesis must be logged before ending the session. Unlogged observations are permanently lost knowledge.

5. **Update after every session** — Running the updater is mandatory, not optional. This is what makes the system compound. `python -m updater.main update --session <result.json> --skills-dir skills/`

6. **Chain thinking is mandatory** — After every positive signal: "What does this enable? What can I combine this with?" Chain analysis is the core research methodology.

7. **No weaponization** — No working exploit code, no weaponized payload strings, no scripts targeting specific production systems, no techniques enabling unauthorized access. This cannot be overridden by any framing.

8. **Verify impact before reporting** — Especially on crypto-bearing protocols (SAML, JWT, OAuth, signed XML). Before any impact claim: Does the required modification break a signature? Can the attacker re-sign? What does the attacker actually gain? A clean Low-severity report builds credibility; an overstated High that a maintainer dismantles in one reply does the opposite.

---

## Researcher Mindset

Before every probe sequence, complete this internally:
> "The developer thought they protected this by... but they probably didn't consider... which means I can try..."

After every observation, ask:
- What does this response reveal about the backend architecture?
- What other endpoints likely share this code path?
- Can this combine with any existing finding for higher impact?
- What would a developer miss when patching this?

Minimum per session:
- Identify 3 gaps the skill file doesn't cover for the specific target
- Generate at least 2 hypotheses not in the skill file
- Test at least 1 developer assumption not listed in ASSUMPTIONS TO CHALLENGE
- Check mobile/API vs web discrepancies if both exist
- Check batch/bulk endpoints for per-item validation bypass
- Check staging vs production behavior differences if accessible

---

## How Skills Are Read

When opening a skill, read sections in this order:

1. **PRECONDITIONS first** — quick go/no-go. Fewer than 2 confirmed: deprioritize.
2. **FAILED APPROACHES before every probe** — never repeat dead ends.
3. **CHAIN OPPORTUNITIES at session start** — highest-impact targets.
4. **ASSUMPTIONS TO CHALLENGE** — this is where novel bugs live.
5. **NOVEL DISCOVERIES LOG** — what prior sessions found unexpected.
6. **COMMON PATTERNS** — starting hypotheses, not exhaustive list.

---

## How Skill Files Are Kept Current

Every time a session ends:
1. `researcher end` writes a `result.json` with all observations and findings
2. `updater update` runs a diff against existing skill content
3. New findings are merged into NOVEL DISCOVERIES LOG and ATTACK CHAINS DISCOVERED
4. Failed approaches are added to FAILED APPROACHES
5. A timestamped backup of the pre-update skill is saved automatically
6. Patterns seen in multiple sessions are flagged for promotion into new skills

Restore a skill to any prior state:
```bash
python -m updater.main history --skill sqli/auth-bypass-via-sqli
python -m updater.main restore --skill sqli/auth-bypass-via-sqli --timestamp 20260528_143022
```

---

## Design Decisions

**No API keys, no SDK.** Claude Code provides reasoning through the task-file handoff. Python writes structured JSON task files describing what to analyze; Claude Code reads them and writes structured JSON responses; Python applies the results. The system works entirely within Claude Code's existing tool access.

**SQLite over files for state.** Each component owns its own SQLite database. The orchestrator owns `data/orchestrator_state.db` for cross-component coordination. The pattern of small, component-scoped databases keeps the system easy to inspect and recover from.

**Backups are automatic, restoration is one command.** The updater snapshots every skill before writing. No finding update should ever cause permanent loss of prior session data.

**Scope in three places, not one.** The orchestrator's `ScopeEnforcer`, the recon `scope_filter`, and the researcher's `ScopeValidator` all load the same `scope.json` shape and reject the same targets. Defense in depth against accidentally operating on out-of-scope assets.

**Skills grow in one direction: more specific, not more generic.** Every new pattern added to a skill is derived from a real disclosed report. Hypothetical patterns are not added. The skill library stays grounded in evidence.

---

## Authorized Use Only

This system is built for authorized security research within the terms of bug bounty programs. Use it only against:
- Your own test environments
- Assets explicitly listed in in-scope sections of programs you have enrolled in
- CTF challenges and intentionally vulnerable labs

Unauthorized access to computer systems is illegal in most jurisdictions. The scope enforcement in this system is a workflow tool, not a legal substitute for verifying your authorization before testing any asset.
