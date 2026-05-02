# SKILL: SQLI — Blind Or Error Based On Corporate Endpoint
**Category:** sqli > blind-or-error-based-on-corporate-endpoint
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Query was assembled by string concatenation rather than parameterized binding, so user-controlled bytes alter the parsed SQL rather than being treated as data.

---

## PRECONDITIONS
- [ ] Endpoint constructs a SQL query whose contents include a user-supplied value
- [ ] Query construction does not use parameterized placeholders for that value
- [ ] Database driver permits the resulting statement to alter query semantics

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: search_endpoint. 

### Phase 2: Active Probing (Authorized Scope Only)
On every parameter that flows into search, lookup, filter, sort, or report-generation endpoints, submit minimally-disruptive markers (single quote, double quote, comment markers, equivalent boolean expressions) and compare responses against an unmodified baseline. Look for: stack-trace style errors, content-length deltas, response-time deltas under boolean conditions, and behavior consistent with parameterized vs concatenated query construction. Confirm by varying the boolean to produce both true and false branches, and check that timing-based payloads produce predictable delays.

### Phase 3: Confirmation
An endpoint returns content shape changes (different result counts, error messages, response timings) when SQL meta-characters or boolean expressions are appended to a parameter, indicating that the value reaches a SQL query without parameterization.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching search_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: An endpoint returns content shape changes (different result counts, error messages, response timings
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Blind Or Error Based On Corporate Endpoint | 1 | search_endpoint | An endpoint returns content shape changes (different result counts, error messag | - |

---

## DETECTION SIGNALS
**Positive signals:**
- An endpoint returns content shape changes (different result counts, error messages, response timings) when SQL meta-characters or boolean expressions are appended to a parameter, indicating that the value reaches a SQL query without parameterization.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- SQLi commonly chains to credential extraction, account takeover via auth-table writes, and (when DB privileges allow) to RCE via UDFs, file writes, or command execution paths.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with sqli this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with sqli this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| rce | Combined with sqli this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Query was assembled by string concatenation rather than parameterized binding, so user-controlled bytes alter the parsed SQL rather than being treated as data.
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
- **Impact statement:** SQLi commonly chains to credential extraction, account takeover via auth-table writes, and (when DB privileges allow) to RCE via UDFs, file writes, or command execution paths.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Query was assembled by string concatenation rather than parameterized binding, so user-controlled bytes alter the parsed SQL rather than being treated as data.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
