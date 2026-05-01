# SKILL: {{ skill_name }}
**Category:** {{ vuln_class }} > {{ vuln_subtype }}
**Severity Range:** {{ severity_range }}
**Typical Payout:** {{ typical_payout }}
**Pattern Count:** {{ pattern_count }}
**Last Updated:** {{ last_updated }}
**Version:** {{ version }}

---

## OVERVIEW
[3-4 sentences derived from `root_cause_pattern` fields. Cover: (1) what the
root cause mechanism is, (2) the attacker's typical impact when this is found,
(3) why developers commonly miss it. Be specific to this vuln_class/subtype.
Minimum 100 characters; do not pad with generic prose.]

---

## PRECONDITIONS
- [ ] [Concrete precondition derived from patterns. Each item must be
  observable on a target before discovery is possible.]
- [ ] [Second precondition...]
- [ ] [Third precondition...]
[Minimum 3, maximum 8. Deduplicate semantically — don't repeat the same
condition with different phrasing. Pull from `preconditions` arrays in input.]

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
[Where to look. What feature categories from `affected_feature_type` to target.
What query patterns / endpoints / asset types map to this vuln class. Pull
from `affected_feature_type` and `affected_stack_hints` in patterns.]

### Phase 2: Active Probing (Authorized Scope Only)
[Behavioral tests safe to run within program scope. If any pattern has
`oob_required: true`, describe the OOB strategy abstractly (sentinel host,
DNS callback) without payload syntax. Otherwise describe in-band probes.
NEVER include exploit payloads or shell commands.]

### Phase 3: Confirmation
[What confirms the finding is real (not a false positive). What additional
signals strengthen the finding. Conditions that escalate severity (e.g.,
"if response includes credentials, treat as critical").]

---

## TESTING WORKFLOW
```
Step 1: <Identify candidate surface>
   ↓
Step 2: <Probe with safe input>
   ↓
Step 3: <Observe behavioral signal>
   ↓
Step 4: <Negative test — confirm signal absent on safe input>
   ↓
Step 5: <Document and report>
```
[5-10 steps. Use `→` arrows. Derived from `detection_approach` fields.]

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| [Short pattern label] | [N] | [feature_type] | [signal one-liner] | [hints] |

[One row per distinct pattern in the input. Frequency = count of patterns
with the same root_cause_pattern shape. Sort by frequency DESC.]

---

## DETECTION SIGNALS
**Positive signals:**
- [Pulled from `behavioral_signal` fields. One bullet per distinct signal.]

**Negative signals (likely false positive):**
- [Conditions that look similar but indicate the vuln is NOT present.
  Inferred from the absence of the root-cause mechanism.]

**Escalation signals:**
- [From `chain_targets` and `chain_reasoning`. What additional findings
  warrant escalation to higher severity.]

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| [target vuln_class] | [combined impact] | [when this chain is reachable] | [high/medium/low] |

[From `chain_targets` arrays. Confidence: `high` if a target appears in
> 2 patterns in this group, `medium` if 1-2, `low` if inferred from
chain_reasoning rather than direct observation.]

---

## ASSUMPTIONS TO CHALLENGE
- [ ] [Developer assumption to violate. Derived from `root_cause_pattern` —
  what assumption did the developer make that the patterns prove wrong?]
- [ ] [Second assumption...]
- [ ] [Third assumption...]
[Minimum 3.]

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
- **Impact statement:** [Template sentence derived from severity range +
  representative chain_reasoning. One line.]
- **CVSS hint:** [Partial vector based on the most common pattern shape.
  Use AV/AC/PR/UI/S/C/I/A short form, e.g., "AV:N/AC:L/PR:N/UI:N/S:C".]
- **Remediation:** [What fix addresses the root cause — derived from
  `root_cause_pattern` (e.g., "Add host allow-list and validate resolved
  DNS against private ranges before fetching").]
- **PoC format:** [What evidence to capture per `detection_approach` —
  abstract description, NOT a payload. E.g., "Screenshot of outbound
  request from server IP to sentinel host; redacted response showing
  internal-only data was reachable."]
