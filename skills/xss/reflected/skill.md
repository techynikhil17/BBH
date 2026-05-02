# SKILL: XSS — Reflected
**Category:** xss > reflected
**Severity Range:** medium
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Developer assumed input was either trusted or escaped earlier in the pipeline, and rendered it into HTML using a templating mode (or string concatenation) that does not apply context-aware encoding by default.

---

## PRECONDITIONS
- [ ] User input is rendered back into an HTML response without server-side or client-side context-aware encoding
- [ ] The reflection occurs in an executable context (HTML body, script, attribute) rather than a strictly text-only sink
- [ ] Behavioral signal observable from outside the application

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: user_profile. 

### Phase 2: Active Probing (Authorized Scope Only)
Identify input fields and URL parameters whose values appear back in the rendered page (search forms, profile fields, error messages, redirect URLs). Submit benign sentinel strings containing special characters relevant to the rendering context (HTML, attribute, JS, URL) and inspect the response markup to determine whether the value was encoded for that context. Where the sentinel appears unencoded inside an executable context, treat the field as potentially XSS-vulnerable and document the reflection vector without crafting a working exploit.

### Phase 3: Confirmation
User-supplied input is reflected into the rendered HTML response of an application page without context-appropriate output encoding, allowing arbitrary script execution in the browser of any user who views the affected page.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching user_profile
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: User-supplied input is reflected into the rendered HTML response of an application page without cont
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Reflected | 1 | user_profile | User-supplied input is reflected into the rendered HTML response of an applicati | - |

---

## DETECTION SIGNALS
**Positive signals:**
- User-supplied input is reflected into the rendered HTML response of an application page without context-appropriate output encoding, allowing arbitrary script execution in the browser of any user who views the affected page.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Reflected XSS in an authenticated context can read CSRF tokens and session storage, enabling state-changing requests on behalf of the victim and effectively bypassing CSRF protections.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with xss this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| csrf | Combined with xss this typically extends impact through the csrf surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Developer assumed input was either trusted or escaped earlier in the pipeline, and rendered it into HTML using a templating mode (or string concatenation) that does not apply context-aware encoding by default.
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
- **Impact statement:** Reflected XSS in an authenticated context can read CSRF tokens and session storage, enabling state-changing requests on behalf of the victim and effectively bypassing CSRF protections.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Developer assumed input was either trusted or escaped earlier in the pipeline, and rendered it into HTML using a templating mode (or string concatenation) that does not apply context-aware encoding by default.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
