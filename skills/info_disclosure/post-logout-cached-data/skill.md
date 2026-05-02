# SKILL: INFO_DISCLOSURE — Post Logout Cached Data
**Category:** info_disclosure > post-logout-cached-data
**Severity Range:** low
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The developer treated logout as a server-side session termination event but did not consider that the browser, intermediate caches, or client-side state retain rendered pages and responses that contained the authenticated user's data. Cache-control headers and client-state-clearing logic were missing from sensitive endpoints.

---

## PRECONDITIONS
- [ ] Application has a logout flow that ends the user session
- [ ] Pages rendered during the session contain user-specific or sensitive data
- [ ] Server responses lack appropriate Cache-Control: no-store / private directives, OR client-side state is not cleared on logout

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: session_management. 

### Phase 2: Active Probing (Authorized Scope Only)
Authenticate as a test user, navigate through pages that display account-specific data, log out via the application's official flow, then attempt to access the same pages via browser back button, browser history, and direct URL re-entry. Inspect HTTP response headers for cache-control directives (no-store, no-cache, private). Check if browser caches sensitive responses, and whether the application invalidates server-side rendered tokens or session cookies on logout. Compare authenticated and unauthenticated response bodies for the same URL after logout.

### Phase 3: Confirmation
After a user logs out, previously rendered pages or cached responses still display sensitive account data when accessed via browser back navigation, history, or cached responses.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching session_management
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: After a user logs out, previously rendered pages or cached responses still display sensitive account
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Post Logout Cached Data | 1 | session_management | After a user logs out, previously rendered pages or cached responses still displ | - |

---

## DETECTION SIGNALS
**Positive signals:**
- After a user logs out, previously rendered pages or cached responses still display sensitive account data when accessed via browser back navigation, history, or cached responses.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- If cached pages contain identifiers (account IDs, session tokens, internal URLs), an attacker with brief physical access or a shared browser can extract those for follow-on IDOR or session-hijack attacks against the same account.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| idor | Combined with info disclosure this typically extends impact through the idor surface | When the target is reachable from the same authentication context | medium |
| auth_bypass | Combined with info disclosure this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The developer treated logout as a server-side session termination event but did not consider that the browser, intermediate caches, or client-side state retain rendered pages and responses that contained the authenticated user's data. Cache-control headers and client-state-clearing logic were missing from sensitive endpoints.
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
- **Impact statement:** If cached pages contain identifiers (account IDs, session tokens, internal URLs), an attacker with brief physical access or a shared browser can extract those for follow-on IDOR or session-hijack attacks against the same account.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The developer treated logout as a server-side session termination event but did not consider that the browser, intermediate caches, or client-side state retain rendered pages and responses that contained the authenticated user's data. Cache-control headers and client-state-clearing logic were missing from sensitive endpoints.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
