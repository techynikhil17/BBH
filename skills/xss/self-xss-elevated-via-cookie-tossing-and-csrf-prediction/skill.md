# SKILL: XSS — Self Xss Elevated Via Cookie Tossing And Csrf Prediction
**Category:** xss > self-xss-elevated-via-cookie-tossing-and-csrf-prediction
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Three weak controls — a self-XSS sink, broad cookie-domain scoping, and a CSRF token whose entropy or binding is insufficient — were each judged independently low-severity, so none was hardened. Together they form a one-click takeover.

---

## PRECONDITIONS
- [ ] Application has at least one XSS sink, even if only self-XSS
- [ ] Cookies set on a sibling subdomain are honored on the privileged subdomain
- [ ] Anti-CSRF token is predictable or derived from a value the attacker can influence

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: auth_endpoint. 

### Phase 2: Active Probing (Authorized Scope Only)
Map every authenticated state-change endpoint and identify which anti-CSRF tokens it accepts. For each token, determine generation source (HMAC of session, random, derived from cookie) and whether the application also reads any value from a cookie that is settable from a sibling subdomain. Identify any XSS sink — even self-XSS — that runs in the application origin. Sketch the chain: attacker primes cookies on a sibling subdomain (subdomain takeover, open subdomain, or attacker-controlled subdomain), uses self-XSS or cookie tossing to inject a value the server later treats as authenticated context, and replays a state-change request whose CSRF token was either predictable or set by the attacker. Look specifically at workflows that auto-approve when the token matches.

### Phase 3: Confirmation
A reflected/self-XSS that initially looks low-impact becomes a one-click takeover when chained with the ability to set cookies on a sibling subdomain (cookie tossing) and a predictable or reusable anti-CSRF token, ultimately auto-approving a privileged action like temporary auth or session elevation.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching auth_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A reflected/self-XSS that initially looks low-impact becomes a one-click takeover when chained with 
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Self Xss Elevated Via Cookie Tossing And Csrf Prediction | 1 | auth_endpoint | A reflected/self-XSS that initially looks low-impact becomes a one-click takeove | - |

---

## DETECTION SIGNALS
**Positive signals:**
- A reflected/self-XSS that initially looks low-impact becomes a one-click takeover when chained with the ability to set cookies on a sibling subdomain (cookie tossing) and a predictable or reusable anti-CSRF token, ultimately auto-approving a privileged action like temporary auth or session elevation.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- This pattern is a textbook chain: XSS provides script execution, cookie scoping provides cross-subdomain influence, CSRF prediction completes the privileged action. Subdomain takeover frequently supplies the cookie-toss origin.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with xss this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| csrf | Combined with xss this typically extends impact through the csrf surface | When the target is reachable from the same authentication context | medium |
| subdomain_takeover | Combined with xss this typically extends impact through the subdomain takeover surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Three weak controls — a self-XSS sink, broad cookie-domain scoping, and a CSRF token whose entropy or binding is insufficient — were each judged independently low-severity, so none was hardened. Together they form a one-click takeover.
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
- **Impact statement:** This pattern is a textbook chain: XSS provides script execution, cookie scoping provides cross-subdomain influence, CSRF prediction completes the privileged action. Subdomain takeover frequently supplies the cookie-toss origin.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Three weak controls — a self-XSS sink, broad cookie-domain scoping, and a CSRF token whose entropy or binding is insufficient — were each judged independently low-severity, so none was hardened. Together they form a one-click takeover.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
