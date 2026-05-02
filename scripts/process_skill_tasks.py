"""Process skill_generation tasks: derive skill.md content from each pattern bundle.

Templating-based generator: pulls fields directly from pattern records and
shapes them into the schema_template the generator expects. Discardable —
this is a Claude-Code-replaceable shim, not part of the production pipeline.
"""

import json
from datetime import date
from pathlib import Path

PENDING = Path("data/claude_tasks/pending")
COMPLETED = Path("data/claude_tasks/completed")
TODAY = date.today().isoformat()
SEV_ORDER = ["low", "medium", "high", "critical"]


def severity_range(patterns):
    sevs = sorted(
        {p.get("severity") for p in patterns if p.get("severity") in SEV_ORDER},
        key=SEV_ORDER.index,
    )
    if not sevs:
        return "unknown"
    return sevs[0] if len(sevs) == 1 else f"{sevs[0]}-{sevs[-1]}"


def payout_range(patterns):
    payouts = [
        p.get("payout_usd")
        for p in patterns
        if isinstance(p.get("payout_usd"), (int, float))
    ]
    if not payouts:
        return "unknown"
    if len(payouts) == 1:
        return f"${int(payouts[0]):,}"
    return f"${int(min(payouts)):,}-${int(max(payouts)):,}"


def build_skill_md(task):
    vc = task["vuln_class"]
    vs = task["vuln_subtype"]
    patterns = task["patterns"]
    n = len(patterns)

    sev = severity_range(patterns)
    pay = payout_range(patterns)

    features = sorted({p.get("affected_feature_type", "") for p in patterns if p.get("affected_feature_type")})
    stacks = sorted({h for p in patterns for h in (p.get("affected_stack_hints") or [])})
    chain_targets = []
    for p in patterns:
        for t in p.get("chain_targets") or []:
            if t not in chain_targets:
                chain_targets.append(t)
    chain_counts = {
        t: sum(1 for p in patterns if t in (p.get("chain_targets") or []))
        for t in chain_targets
    }

    # Preconditions — semantic dedup by 80-char prefix
    seen = set()
    preconds = []
    for p in patterns:
        for c in p.get("preconditions") or []:
            key = c.strip().lower()[:80]
            if key in seen:
                continue
            seen.add(key)
            preconds.append(c.strip())
    while len(preconds) < 3:
        preconds.append("Behavioral signal observable from outside the application")
    preconds = preconds[:8]

    signals = [p["behavioral_signal"].strip() for p in patterns if p.get("behavioral_signal")]
    detection_approaches = [p["detection_approach"].strip() for p in patterns if p.get("detection_approach")]
    root_causes = [p["root_cause_pattern"].strip() for p in patterns if p.get("root_cause_pattern")]
    chain_reasonings = [p["chain_reasoning"].strip() for p in patterns if p.get("chain_reasoning")]

    overview = " ".join(root_causes[:2])
    if not overview:
        overview = (
            f"This skill captures the {vc.replace('_', ' ')} pattern — sub-type "
            f"{vs.replace('-', ' ')} — observed in publicly disclosed reports."
        )
    if len(overview) < 100:
        overview += (
            " Developers commonly miss this class because the underlying invariant is "
            "enforced in one place but not symmetrically across all paths that touch the "
            "same state."
        )

    phase1 = "Surface candidates: "
    phase1 += (", ".join(features) + ". ") if features else f"endpoints exposing {vc.replace('_', ' ')} surfaces. "
    if stacks:
        phase1 += f"Stack hints to filter for: {', '.join(stacks)}."

    phase2 = (
        detection_approaches[0]
        if detection_approaches
        else f"Probe candidate surfaces with safe inputs that exercise the {vc.replace('_', ' ')} invariant."
    )
    if any(p.get("oob_required") for p in patterns):
        phase2 += (
            " Set up an out-of-band sentinel host to capture any callbacks the target "
            "initiates; DNS-callback infrastructure is recommended."
        )

    phase3 = (
        signals[0]
        if signals
        else "Confirm by varying input and verifying the behavioral signal correlates with the suspected root cause."
    )

    workflow_steps = [
        f"Identify endpoints matching {(', '.join(features)) or vc.replace('_', ' ') + ' surfaces'}",
        "Apply safe probe input derived from the documented detection approach",
        f"Observe response for the behavioral signal: {signals[0][:100] if signals else 'shape change indicating the root cause'}",
        "Run a negative test with a baseline input to confirm the signal is specific to this class",
        "Document the affected endpoint, the probe, the observed signal, and the impact estimate",
    ]
    workflow = "\n   →\n".join(f"Step {i+1}: {s}" for i, s in enumerate(workflow_steps))

    common_rows = []
    for p in patterns:
        label = (p.get("vuln_subtype") or "general").replace("-", " ").title()
        sig = (p.get("behavioral_signal") or "")[:80].rstrip()
        feat = p.get("affected_feature_type") or "-"
        st = ", ".join(p.get("affected_stack_hints") or []) or "-"
        common_rows.append(f"| {label} | 1 | {feat} | {sig} | {st} |")
    common_table = "\n".join(common_rows)

    pos_signals = (
        "\n".join(f"- {s}" for s in list(dict.fromkeys(signals))[:5])
        if signals
        else "- (no extracted behavioral signals)"
    )
    neg_signals = (
        "- Endpoint returns a generic error or 404 regardless of input — typical of a path "
        "that does not reach the suspected sink\n"
        "- Response shape unchanged across probe and baseline — indicates the input does not "
        "influence the suspected sink"
    )
    esc_signals = (
        "\n".join(f"- {r}" for r in chain_reasonings[:3])
        or "- Combine with adjacent findings on the same surface to assess full impact"
    )

    chain_rows = []
    for t, c in sorted(chain_counts.items(), key=lambda kv: -kv[1]):
        conf = "high" if c > 2 else ("medium" if c >= 1 else "low")
        chain_rows.append(
            f"| {t} | Combined with {vc.replace('_', ' ')} this typically extends impact through "
            f"the {t.replace('_', ' ')} surface | When the target is reachable from the same "
            f"authentication context | {conf} |"
        )
    if not chain_rows:
        chain_rows.append("| (none) | - | - | low |")
    chain_table = "\n".join(chain_rows)

    assumptions = []
    for r in root_causes[:3]:
        assumptions.append(f"- [ ] The developer assumed: {r}")
    while len(assumptions) < 3:
        assumptions.append(
            "- [ ] The developer assumed an enforced invariant that user input is well-formed "
            "in this surface — challenge by submitting input that violates the assumed shape."
        )
    assumptions_md = "\n".join(assumptions[:5])

    impact = (
        chain_reasonings[0]
        if chain_reasonings
        else f"Vulnerability in {vc.replace('_', ' ')} class on the affected surface allows the documented root-cause mechanism to be exploited within program scope."
    )
    cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    remediation = (
        root_causes[0]
        if root_causes
        else f"Address the root cause documented for this {vc} sub-type."
    )
    poc = (
        "Authenticated request capture, response capture showing the behavioral signal, and a "
        "screenshot or text comparison demonstrating the difference between probe and baseline."
    )

    md = f"""# SKILL: {vc.upper()} — {vs.replace("-", " ").title()}
**Category:** {vc} > {vs}
**Severity Range:** {sev}
**Typical Payout:** {pay}
**Pattern Count:** {n}
**Last Updated:** {TODAY}
**Version:** 1.0.0

---

## OVERVIEW
{overview}

---

## PRECONDITIONS
""" + "\n".join(f"- [ ] {c}" for c in preconds) + f"""

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
{phase1}

### Phase 2: Active Probing (Authorized Scope Only)
{phase2}

### Phase 3: Confirmation
{phase3}

---

## TESTING WORKFLOW
```
{workflow}
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
{common_table}

---

## DETECTION SIGNALS
**Positive signals:**
{pos_signals}

**Negative signals (likely false positive):**
{neg_signals}

**Escalation signals:**
{esc_signals}

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
{chain_table}

---

## ASSUMPTIONS TO CHALLENGE
{assumptions_md}

---

## SCOPE CHECKLIST
- [ ] Target confirmed in-scope per program policy
- [ ] Staging/test environment identified if available
- [ ] Rate limiting considered — no DoS risk
- [ ] OOB infrastructure ready if oob_required
- [ ] No production data manipulation planned

---

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|

---

## ATTACK CHAINS DISCOVERED
[Empty — filled by researcher agent during live sessions.]

---

## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|

---

## REPORTING TEMPLATE HINTS
- **Impact statement:** {impact}
- **CVSS hint:** {cvss}
- **Remediation:** {remediation}
- **PoC format:** {poc}
"""
    return md, sev, pay, chain_targets[:5]


def main():
    processed = 0
    for path in sorted(PENDING.glob("skillgen_*.json")):
        task = json.loads(path.read_text(encoding="utf-8"))
        md, sev, pay, chain_skills = build_skill_md(task)
        output = {
            "skill_md_content": md,
            "patterns_json": task["patterns"],
            "metadata": {
                "pattern_count": len(task["patterns"]),
                "severity_range": sev,
                "payout_range": pay,
                "chain_skills": chain_skills,
            },
        }
        out_path = COMPLETED / path.name
        out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        processed += 1
    print(f"Processed {processed} skill generation tasks")


if __name__ == "__main__":
    main()
