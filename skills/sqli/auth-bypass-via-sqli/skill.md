# SKILL: SQLI — Auth Bypass Via Sqli
**Category:** sqli > auth-bypass-via-sqli
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
User input was concatenated into the SQL predicate that decides which user record the login resolves to, so an attacker can both authenticate successfully and choose which user to authenticate as.

---

## PRECONDITIONS
- [ ] Authentication path constructs a SQL query string with concatenated user input
- [ ] User-record selection is the authority for who the resulting session represents
- [ ] No layer downstream re-validates that the supplied password matches the resolved user

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: auth_endpoint. 

### Phase 2: Active Probing (Authorized Scope Only)
On each authentication or password-reset endpoint, inventory every parameter that flows into the user-lookup query (username, email, tenant id, any pre-auth context). For each, test whether SQL meta-characters change the response shape (login success without correct password, different error messages, time-based delays). Confirm by comparing authenticated session contents across attempts — escalation to admin or arbitrary user typically indicates the lookup predicate is being subverted, not just an error path.

### Phase 3: Confirmation
An authentication endpoint accepts crafted login input and returns a session for an account other than the one whose credentials were submitted, indicating the SQL query that selects the user record is influenced by attacker-controlled fragments.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching auth_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: An authentication endpoint accepts crafted login input and returns a session for an account other th
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Auth Bypass Via Sqli | 1 | auth_endpoint | An authentication endpoint accepts crafted login input and returns a session for | - |

---

## DETECTION SIGNALS
**Positive signals:**
- An authentication endpoint accepts crafted login input and returns a session for an account other than the one whose credentials were submitted, indicating the SQL query that selects the user record is influenced by attacker-controlled fragments.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- SQLi in the auth path is a top-of-funnel primitive — combined with admin-flag selection it yields full account takeover, and admin sessions in chat / collaboration platforms commonly expose code-execution surfaces (integration scripts, webhook handlers) that complete the chain to RCE.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with sqli this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with sqli this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| rce | Combined with sqli this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: User input was concatenated into the SQL predicate that decides which user record the login resolves to, so an attacker can both authenticate successfully and choose which user to authenticate as.
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
- **Impact statement:** SQLi in the auth path is a top-of-funnel primitive — combined with admin-flag selection it yields full account takeover, and admin sessions in chat / collaboration platforms commonly expose code-execution surfaces (integration scripts, webhook handlers) that complete the chain to RCE.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** User input was concatenated into the SQL predicate that decides which user record the login resolves to, so an attacker can both authenticate successfully and choose which user to authenticate as.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
