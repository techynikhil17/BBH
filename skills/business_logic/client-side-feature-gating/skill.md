# SKILL: BUSINESS_LOGIC — Client Side Feature Gating
**Category:** business_logic > client-side-feature-gating
**Severity Range:** high
**Typical Payout:** $3,000
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The developer enforced the entitlement only at the UI / display layer (hide the toggle for non-premium users) instead of on the server when the preference write happens, so any client that posts the underlying preference value bypasses the gate.

---

## PRECONDITIONS
- [ ] Application offers a feature gated behind a paid tier
- [ ] The gating is partly or fully expressed as a user preference flag stored on the user record
- [ ] Preference-update endpoint does not re-validate the actor's tier before persisting the new value

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: subscription_management. 

### Phase 2: Active Probing (Authorized Scope Only)
Identify endpoints that update user preferences linked to paid features (ad-free, advanced settings, premium toggles). As a free/non-entitled user, attempt to write the preference directly via the API or by replaying the request a paid user would send. Compare server response and resulting account state — a successful write that produces the entitlement is a privilege check bypass. Repeat across endpoints that read or write subscription-affecting flags, watching for any path that lacks an entitlement re-check.

### Phase 3: Confirmation
A user-modifiable preference (ad display, theme, feature flag) toggles a paid/premium-only feature without the server re-validating the user's entitlement on each preference write.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching subscription_management
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A user-modifiable preference (ad display, theme, feature flag) toggles a paid/premium-only feature w
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Client Side Feature Gating | 1 | subscription_management | A user-modifiable preference (ad display, theme, feature flag) toggles a paid/pr | - |

---

## DETECTION SIGNALS
**Positive signals:**
- A user-modifiable preference (ad display, theme, feature flag) toggles a paid/premium-only feature without the server re-validating the user's entitlement on each preference write.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Often this same endpoint is also susceptible to mass-assignment style abuse where additional account-tier flags can be smuggled into the same write.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| mass_assignment | Combined with business logic this typically extends impact through the mass assignment surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The developer enforced the entitlement only at the UI / display layer (hide the toggle for non-premium users) instead of on the server when the preference write happens, so any client that posts the underlying preference value bypasses the gate.
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
- **Impact statement:** Often this same endpoint is also susceptible to mass-assignment style abuse where additional account-tier flags can be smuggled into the same write.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The developer enforced the entitlement only at the UI / display layer (hide the toggle for non-premium users) instead of on the server when the preference write happens, so any client that posts the underlying preference value bypasses the gate.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
