# SKILL: <Vulnerability Name>
**Category:** <vuln_class> > <vuln_subtype>
**Severity Range:** <e.g., medium-critical>
**Typical Payout:** <e.g., $500–$5,000>
**Pattern Count:** <N>
**Last Updated:** <YYYY-MM-DD>
**Version:** 1.0.0

---

## OVERVIEW
<3-4 sentences: root cause, attacker impact, why developers miss it.>

---

## PRECONDITIONS
- [ ] <Precondition 1>
- [ ] <Precondition 2>
- [ ] <Precondition 3>

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
<Where to look, what features to target.>

### Phase 2: Active Probing (Authorized Scope Only)
<Safe behavioral tests, OOB strategy if applicable.>

### Phase 3: Confirmation
<What confirms the finding. False positive indicators. Escalation conditions.>

---

## TESTING WORKFLOW
```
Step 1: <Identify candidate surface>
   ↓
Step 2: <Probe with safe input>
   ↓
Step 3: <Observe behavioral signal>
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|

---

## DETECTION SIGNALS
**Positive signals:**
-

**Negative signals (likely false positive):**
-

**Escalation signals:**
-

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|

---

## ASSUMPTIONS TO CHALLENGE
- [ ] <Assumption 1>
- [ ] <Assumption 2>
- [ ] <Assumption 3>

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


---

## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|

---

## REPORTING TEMPLATE HINTS
- **Impact statement:**
- **CVSS hint:**
- **Remediation:**
- **PoC format:**
