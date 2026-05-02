# SKILL: SSRF — Ipv6 Nat64 Allowlist Bypass
**Category:** ssrf > ipv6-nat64-allowlist-bypass
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The SSRF defense was implemented as a curated deny-list of address ranges rather than a positive allow-list of explicitly-permitted destinations, and the curator did not enumerate the full IPv6 special-purpose registry; an entire address family slipped through.

---

## PRECONDITIONS
- [ ] Endpoint fetches a user-supplied URL server-side
- [ ] Anti-SSRF logic relies on a deny-list of address ranges rather than a positive allow-list of destinations
- [ ] Deployment network routes the missing prefix to internal targets

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: url_import. Stack hints to filter for: ipv6.

### Phase 2: Active Probing (Authorized Scope Only)
Identify endpoints that accept user-supplied URLs and fetch them server-side. Read the SSRF allow-list / deny-list logic and enumerate the address ranges it covers. Compare against the full list of IPv6 special-purpose registries (loopback, link-local, unique-local, IPv4-mapped, IPv4-translated, NAT64 well-known and local-use, Teredo, ORCHID, documentation, 6to4). Submit URLs whose host resolves to addresses in each missing range and observe whether the server fetches them. Pay special attention to deployment environments that route NAT64 prefixes — a working request indicates the deny-list does not cover that prefix.

### Phase 3: Confirmation
An SSRF protection layer that blocks well-known private/loopback ranges still permits requests to internal targets when the address is expressed via a less common IPv6 prefix (NAT64 local-use, 6to4, mapped IPv4, link-local). The fetch endpoint succeeds for an address that resolves to an internal route in the deployment environment.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching url_import
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: An SSRF protection layer that blocks well-known private/loopback ranges still permits requests to in
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Ipv6 Nat64 Allowlist Bypass | 1 | url_import | An SSRF protection layer that blocks well-known private/loopback ranges still pe | ipv6 |

---

## DETECTION SIGNALS
**Positive signals:**
- An SSRF protection layer that blocks well-known private/loopback ranges still permits requests to internal targets when the address is expressed via a less common IPv6 prefix (NAT64 local-use, 6to4, mapped IPv4, link-local). The fetch endpoint succeeds for an address that resolves to an internal route in the deployment environment.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Once the SSRF reaches an internal address, common follow-ons are cloud metadata exposure (credentials → privilege escalation), internal-only admin services, and unauthenticated dev/debug endpoints — same chain shape as IPv4 SSRF.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | Combined with ssrf this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |
| rce | Combined with ssrf this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The SSRF defense was implemented as a curated deny-list of address ranges rather than a positive allow-list of explicitly-permitted destinations, and the curator did not enumerate the full IPv6 special-purpose registry; an entire address family slipped through.
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
- **Impact statement:** Once the SSRF reaches an internal address, common follow-ons are cloud metadata exposure (credentials → privilege escalation), internal-only admin services, and unauthenticated dev/debug endpoints — same chain shape as IPv4 SSRF.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The SSRF defense was implemented as a curated deny-list of address ranges rather than a positive allow-list of explicitly-permitted destinations, and the curator did not enumerate the full IPv6 special-purpose registry; an entire address family slipped through.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
