# SKILL: SQLI — Unauthenticated Post Without Csrf
**Category:** sqli > unauthenticated-post-without-csrf
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
An endpoint exposed to anonymous traffic concatenated user-supplied bytes into a SQL statement; absence of authentication amplifies a classic SQLi root cause into a high-traffic, low-effort exploit surface.

---

## PRECONDITIONS
- [ ] Endpoint accepts unauthenticated requests
- [ ] Body parameter flows into a SQL query without parameterized binding
- [ ] Response shape varies with the parsed query (error, content-length, timing)

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: api_endpoint. 

### Phase 2: Active Probing (Authorized Scope Only)
Map every POST endpoint that does not require authentication and inventory the parameters in its request body. For each parameter, submit minimally-disruptive SQL markers and compare responses against an unmodified baseline — error messages, content-length deltas, timing differences. Audit the same endpoints for additional injection sinks (stored XSS via display fields) since unauthenticated public-facing writes commonly accumulate multiple weaknesses on the same surface.

### Phase 3: Confirmation
A POST endpoint accepts requests without authentication and without a CSRF token, and a parameter in its body reaches a SQL query whose response shape changes when SQL meta-characters or boolean expressions are submitted.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching api_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A POST endpoint accepts requests without authentication and without a CSRF token, and a parameter in
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Unauthenticated Post Without Csrf | 1 | api_endpoint | A POST endpoint accepts requests without authentication and without a CSRF token | - |

---

## DETECTION SIGNALS
**Positive signals:**
- A POST endpoint accepts requests without authentication and without a CSRF token, and a parameter in its body reaches a SQL query whose response shape changes when SQL meta-characters or boolean expressions are submitted.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Unauthenticated SQLi compounds with stored XSS on the same surface — an attacker can plant payloads at scale and harvest authenticated session cookies or admin credentials, then pivot via the SQLi-extracted database contents.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with sqli this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with sqli this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| xss | Combined with sqli this typically extends impact through the xss surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: An endpoint exposed to anonymous traffic concatenated user-supplied bytes into a SQL statement; absence of authentication amplifies a classic SQLi root cause into a high-traffic, low-effort exploit surface.
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
- **Impact statement:** Unauthenticated SQLi compounds with stored XSS on the same surface — an attacker can plant payloads at scale and harvest authenticated session cookies or admin credentials, then pivot via the SQLi-extracted database contents.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** An endpoint exposed to anonymous traffic concatenated user-supplied bytes into a SQL statement; absence of authentication amplifies a classic SQLi root cause into a high-traffic, low-effort exploit surface.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
