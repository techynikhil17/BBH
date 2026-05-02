# SKILL: PROTOTYPE_POLLUTION — Header Name As Prototype Key Causes Uncaught Typeerror
**Category:** prototype_pollution > header-name-as-prototype-key-causes-uncaught-typeerror
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Untrusted strings were used as keys on a plain-prototype object, so reserved JS keys like `__proto__` overwrite or access prototype slots, breaking later property operations and surfacing as an unhandled TypeError.

---

## PRECONDITIONS
- [ ] Service is implemented in JavaScript / Node.js
- [ ] Header-handling code uses plain objects rather than null-prototype maps for header storage
- [ ] At least one path assigns or reads a property keyed by an attacker-controlled header name

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: api_endpoint. Stack hints to filter for: node.js.

### Phase 2: Active Probing (Authorized Scope Only)
Identify Node.js services and middlewares that read request headers via index access on plain objects (e.g. `headers[name]`, destructuring header maps into helpers). Send requests that include header names of the form `__proto__`, `constructor`, `prototype`, `toString`, `hasOwnProperty`. Observe response behavior — process crash, 500 with stack trace mentioning property assignment on a primitive, or hangs are signals that an inherited property has been overwritten or accessed as a callable. Re-test through any path that aggregates or normalizes headers (req.headersDistinct, normalize-headers helpers).

### Phase 3: Confirmation
Sending a request whose header name matches a JavaScript object special key (e.g. `__proto__`, `constructor`, `toString`) crashes the server process with an uncaught TypeError, because downstream code treats the headers structure like a plain object.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching api_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: Sending a request whose header name matches a JavaScript object special key (e.g. `__proto__`, `cons
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Header Name As Prototype Key Causes Uncaught Typeerror | 1 | api_endpoint | Sending a request whose header name matches a JavaScript object special key (e.g | node.js |

---

## DETECTION SIGNALS
**Positive signals:**
- Sending a request whose header name matches a JavaScript object special key (e.g. `__proto__`, `constructor`, `toString`) crashes the server process with an uncaught TypeError, because downstream code treats the headers structure like a plain object.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- On its own this is a denial primitive; the practical chain is amplification — repeated crashing requests against a service without per-source backoff multiplies into a sustained outage.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| rate_limit_bypass | Combined with prototype pollution this typically extends impact through the rate limit bypass surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Untrusted strings were used as keys on a plain-prototype object, so reserved JS keys like `__proto__` overwrite or access prototype slots, breaking later property operations and surfacing as an unhandled TypeError.
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
- **Impact statement:** On its own this is a denial primitive; the practical chain is amplification — repeated crashing requests against a service without per-source backoff multiplies into a sustained outage.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Untrusted strings were used as keys on a plain-prototype object, so reserved JS keys like `__proto__` overwrite or access prototype slots, breaking later property operations and surfacing as an unhandled TypeError.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
