# SKILL: IDOR — Missing Authorization On Import Upload
**Category:** idor > missing-authorization-on-import-upload
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Authorization was performed at job-initiation time but the subsequent upload endpoint trusted the identifier alone, breaking the invariant that the writer must equal the owner of the resource.

---

## PRECONDITIONS
- [ ] Multi-step workflow where the artifact upload uses only an identifier issued in an earlier step
- [ ] Upload step does not re-validate that the requesting session owns the identifier
- [ ] Identifiers are guessable, leakable, or otherwise enumerable across tenants

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: import_function. 

### Phase 2: Active Probing (Authorized Scope Only)
Identify all endpoints that ingest or replace large artifacts addressed by an opaque identifier (imports, exports, migrations, snapshots, batch jobs). For each, authenticate as a low-privilege user and submit a write addressed to an identifier owned by a different user/account. Confirm whether the write succeeds and whether the resulting artifact is later served to the original owner. Pay attention to multi-step flows where the initial authorization happens at job-creation but the file-upload sub-step relies only on the identifier.

### Phase 3: Confirmation
An upload or replacement endpoint that takes a resource identifier (migration id, export id, batch id) accepts a write from a requester who has no relationship to the resource, allowing arbitrary overwrite of another tenant's artifact.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching import_function
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: An upload or replacement endpoint that takes a resource identifier (migration id, export id, batch i
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Missing Authorization On Import Upload | 1 | import_function | An upload or replacement endpoint that takes a resource identifier (migration id | - |

---

## DETECTION SIGNALS
**Positive signals:**
- An upload or replacement endpoint that takes a resource identifier (migration id, export id, batch id) accepts a write from a requester who has no relationship to the resource, allowing arbitrary overwrite of another tenant's artifact.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Overwriting another tenant's import artifact lets an attacker plant content the victim later trusts (configuration, code, exported records) — a classic cross-tenant data integrity primitive that supports follow-on takeover and disclosure.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | Combined with idor this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| business_logic | Combined with idor this typically extends impact through the business logic surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Authorization was performed at job-initiation time but the subsequent upload endpoint trusted the identifier alone, breaking the invariant that the writer must equal the owner of the resource.
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
- **Impact statement:** Overwriting another tenant's import artifact lets an attacker plant content the victim later trusts (configuration, code, exported records) — a classic cross-tenant data integrity primitive that supports follow-on takeover and disclosure.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Authorization was performed at job-initiation time but the subsequent upload endpoint trusted the identifier alone, breaking the invariant that the writer must equal the owner of the resource.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
