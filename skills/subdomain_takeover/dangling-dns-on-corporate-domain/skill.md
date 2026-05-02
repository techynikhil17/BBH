# SKILL: SUBDOMAIN_TAKEOVER — Dangling Dns On Corporate Domain
**Category:** subdomain_takeover > dangling-dns-on-corporate-domain
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The DNS record outlived the third-party resource it referenced — the operator who decommissioned the resource did not also remove the pointing record, and there is no scheduled audit that catches the resulting orphan.

---

## PRECONDITIONS
- [ ] Organization owns DNS records pointing at third-party services
- [ ] At least one such third-party resource is no longer claimed by the organization
- [ ] The provider does not enforce ownership re-verification when the resource is re-registered

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: redirect_handler. 

### Phase 2: Active Probing (Authorized Scope Only)
Enumerate the target organization's subdomains via certificate transparency logs, public DNS data, passive DNS feeds, and any internal asset inventory available. Resolve each subdomain and follow CNAMEs. For records pointing at third-party services, request the resource and compare the response to a maintained set of takeover-eligible fingerprints per provider. Re-run periodically — third-party fingerprints change as services rebrand or restructure their unclaimed-resource responses, and asset inventories drift.

### Phase 3: Confirmation
A subdomain of the target organization resolves to a third-party host whose response indicates the resource has been decommissioned or is unclaimed at that provider, while the parent organization's DNS still points at it.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching redirect_handler
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A subdomain of the target organization resolves to a third-party host whose response indicates the r
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Dangling Dns On Corporate Domain | 1 | redirect_handler | A subdomain of the target organization resolves to a third-party host whose resp | - |

---

## DETECTION SIGNALS
**Positive signals:**
- A subdomain of the target organization resolves to a third-party host whose response indicates the resource has been decommissioned or is unclaimed at that provider, while the parent organization's DNS still points at it.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Controlling a subdomain in the target's domain unlocks cookie scoping, CORS exemptions, OAuth callback abuse, and trust-by-name attacks against users.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| xss | Combined with subdomain takeover this typically extends impact through the xss surface | When the target is reachable from the same authentication context | medium |
| oauth_misconfig | Combined with subdomain takeover this typically extends impact through the oauth misconfig surface | When the target is reachable from the same authentication context | medium |
| cors_misconfig | Combined with subdomain takeover this typically extends impact through the cors misconfig surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The DNS record outlived the third-party resource it referenced — the operator who decommissioned the resource did not also remove the pointing record, and there is no scheduled audit that catches the resulting orphan.
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
- **Impact statement:** Controlling a subdomain in the target's domain unlocks cookie scoping, CORS exemptions, OAuth callback abuse, and trust-by-name attacks against users.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The DNS record outlived the third-party resource it referenced — the operator who decommissioned the resource did not also remove the pointing record, and there is no scheduled audit that catches the resulting orphan.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
