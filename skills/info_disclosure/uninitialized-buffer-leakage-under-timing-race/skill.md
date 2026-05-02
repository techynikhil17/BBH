# SKILL: INFO_DISCLOSURE — Uninitialized Buffer Leakage Under Timing Race
**Category:** info_disclosure > uninitialized-buffer-leakage-under-timing-race
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
An optimization that pooled buffers across operations broke the zero-fill invariant the allocator's API contract promised; the contract was no longer enforced on every code path.

---

## PRECONDITIONS
- [ ] Runtime offers an allocation API documented as returning zeroed memory
- [ ] Implementation has an optimized path (timeout/pool/preallocated cache) that may elide the zero-fill
- [ ] Adjacent operations write sensitive bytes into the memory pool used to satisfy the allocation

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: api_endpoint. Stack hints to filter for: node.js.

### Phase 2: Active Probing (Authorized Scope Only)
For runtimes that expose ostensibly-zero allocators, audit the implementation path that fulfills the allocation, paying attention to any optimization that elides the zero-fill under a timeout, pool-reuse, or resource-pressure code path. Build a probe that requests many fresh allocations under load and inspects them for non-zero bytes. Where the runtime is application-embedded (Node.js, Python, JVM), feed externally-supplied requests that consume large buffers and immediately request fresh allocations — the residue indicates either a missing zero-fill or a write-after-free into a returned-to-pool buffer.

### Phase 3: Confirmation
Allocations that are documented as zero-filled (e.g., Buffer.alloc) sometimes contain data from prior operations when a specific timing condition holds — observable as residual application data in buffers handed to a fresh request.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching api_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: Allocations that are documented as zero-filled (e.g., Buffer.alloc) sometimes contain data from prio
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Uninitialized Buffer Leakage Under Timing Race | 1 | api_endpoint | Allocations that are documented as zero-filled (e.g., Buffer.alloc) sometimes co | node.js |

---

## DETECTION SIGNALS
**Positive signals:**
- Allocations that are documented as zero-filled (e.g., Buffer.alloc) sometimes contain data from prior operations when a specific timing condition holds — observable as residual application data in buffers handed to a fresh request.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Cross-request memory leakage in a multi-tenant runtime can leak session secrets, request bodies, and credentials between unrelated users — a one-way disclosure primitive that supports follow-on takeover.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | Combined with info disclosure this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: An optimization that pooled buffers across operations broke the zero-fill invariant the allocator's API contract promised; the contract was no longer enforced on every code path.
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
- **Impact statement:** Cross-request memory leakage in a multi-tenant runtime can leak session secrets, request bodies, and credentials between unrelated users — a one-way disclosure primitive that supports follow-on takeover.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** An optimization that pooled buffers across operations broke the zero-fill invariant the allocator's API contract promised; the contract was no longer enforced on every code path.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
