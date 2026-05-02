# SKILL: BUSINESS_LOGIC — Uncaught Exception In Tls Callback
**Category:** business_logic > uncaught-exception-in-tls-callback
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Exception isolation was added at one callback site but not symmetrically at the parallel callbacks invoked through the same setup path; the developer fixed the reported instance and did not audit sibling callbacks for the same shape.

---

## PRECONDITIONS
- [ ] Service exposes a network listener that invokes user-provided or library callbacks during connection setup
- [ ] Callback is invoked synchronously and a thrown exception escapes the connection-scoped error handler
- [ ] Process / worker has no other layer that catches and isolates the failure

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: session_token_endpoint. Stack hints to filter for: node.js, tls.

### Phase 2: Active Probing (Authorized Scope Only)
Inventory user-reachable callbacks invoked during early connection setup (TLS SNI/ALPN selection, protocol upgrades, auth challenge handlers). Audit each call site for whether the runtime wraps the callback in a try/catch and routes thrown exceptions through the connection's error path. Where a callback's input is attacker-controlled (e.g., SNI host string, ALPN name list), test whether crafted inputs produce runtime errors (type errors, range errors, undefined property access) and whether those exceptions bubble past the connection layer to crash the process. Inspect changelogs for sibling fixes — when one callback was patched, others on the same code path are commonly missed.

### Phase 3: Confirmation
A network-facing service crashes its process or worker when a client triggers a code path through a callback that throws synchronously, with no try/catch boundary upstream.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching session_token_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A network-facing service crashes its process or worker when a client triggers a code path through a 
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Uncaught Exception In Tls Callback | 1 | session_token_endpoint | A network-facing service crashes its process or worker when a client triggers a | node.js, tls |

---

## DETECTION SIGNALS
**Positive signals:**
- A network-facing service crashes its process or worker when a client triggers a code path through a callback that throws synchronously, with no try/catch boundary upstream.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Crashing-on-input gives an attacker a denial primitive that can be amplified when the listener has no rate limit or cooldown on connection-setup failures.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| rate_limit_bypass | Combined with business logic this typically extends impact through the rate limit bypass surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Exception isolation was added at one callback site but not symmetrically at the parallel callbacks invoked through the same setup path; the developer fixed the reported instance and did not audit sibling callbacks for the same shape.
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
- **Impact statement:** Crashing-on-input gives an attacker a denial primitive that can be amplified when the listener has no rate limit or cooldown on connection-setup failures.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Exception isolation was added at one callback site but not symmetrically at the parallel callbacks invoked through the same setup path; the developer fixed the reported instance and did not audit sibling callbacks for the same shape.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
