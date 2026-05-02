# SKILL: SQLI — Error And Time Based Blind On Theme Selector
**Category:** sqli > error-and-time-based-blind-on-theme-selector
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Preference values were treated as opaque metadata and concatenated into a SQL statement; the developer's mental model of 'this is just a configuration string' did not extend to escaping at the query layer.

---

## PRECONDITIONS
- [ ] Preference value is used in a SQL query without parameterized binding
- [ ] Database driver permits the resulting clause to alter query semantics or stall execution
- [ ] Response timing or shape is observable to the requester

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: user_profile. Stack hints to filter for: mysql.

### Phase 2: Active Probing (Authorized Scope Only)
On every user-preference setter or selector, identify which database table/column the value resolves against. Submit injection markers and observe error-style and content-length responses; if uniform, switch to time-based detection by appending sleep-equivalent boolean clauses and comparing response times across true/false branches. Confirm by paginating extraction across a small number of probe values to validate the response signal is repeatable.

### Phase 3: Confirmation
A user-preference parameter (theme name, locale, sort order) flows into a SQL lookup whose response shape changes when SQL meta-characters or boolean conditions are submitted, and a timing-based boolean payload produces predictable response delays.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching user_profile
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A user-preference parameter (theme name, locale, sort order) flows into a SQL lookup whose response 
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Error And Time Based Blind On Theme Selector | 1 | user_profile | A user-preference parameter (theme name, locale, sort order) flows into a SQL lo | mysql |

---

## DETECTION SIGNALS
**Positive signals:**
- A user-preference parameter (theme name, locale, sort order) flows into a SQL lookup whose response shape changes when SQL meta-characters or boolean conditions are submitted, and a timing-based boolean payload produces predictable response delays.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Once arbitrary SQL is reachable, the standard escalation path is enumeration of authentication and payment tables, followed by credential extraction or auth-table writes.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | Combined with sqli this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| auth_bypass | Combined with sqli this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Preference values were treated as opaque metadata and concatenated into a SQL statement; the developer's mental model of 'this is just a configuration string' did not extend to escaping at the query layer.
- [ ] The developer assumed an enforced invariant that user input is well-formed in this surface — challenge by submitting input that violates the assumed shape.
- [ ] The developer assumed an enforced invariant that user input is well-formed in this surface — challenge by submitting input that violates the assumed shape.

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
- **Impact statement:** Once arbitrary SQL is reachable, the standard escalation path is enumeration of authentication and payment tables, followed by credential extraction or auth-table writes.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Preference values were treated as opaque metadata and concatenated into a SQL statement; the developer's mental model of 'this is just a configuration string' did not extend to escaping at the query layer.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
