# SKILL: INFO_DISCLOSURE — Shared Mutable State Leaks Session Cookie Across Loads
**Category:** info_disclosure > shared-mutable-state-leaks-session-cookie-across-loads
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Lifetime / scope mismatch: configuration meant to be per-navigation was stored in process-global state, so a header bound to one origin's session is sent on the next navigation regardless of destination.

---

## PRECONDITIONS
- [ ] App embeds a WebView or HTTP client that loads multiple distinct origins over its lifetime
- [ ] Request configuration is stored in static / shared / singleton state rather than per-navigation
- [ ] The configuration includes authentication headers or cookies bound to one of the loaded origins

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: session_management. Stack hints to filter for: android, webview.

### Phase 2: Active Probing (Authorized Scope Only)
For each WebView or in-app browser that loads multiple destinations, inspect how request headers and cookies are configured. Identify any state held in static or singleton storage (CUSTOM_HEADERS, defaultHeaders, sessionDefault). Trace whether navigation to a new origin clears or scopes that state. Trigger a navigation that originally set authenticated headers, then navigate to an attacker-controlled origin within the same component and observe the outbound request — leaked headers indicate cross-origin state retention. Combine with Cookie/Authorization-bearing flows to confirm session leakage. Set up an out-of-band sentinel host to capture any callbacks the target initiates; DNS-callback infrastructure is recommended.

### Phase 3: Confirmation
A WebView or HTTP-client component reuses request configuration (custom headers, cookies, auth tokens) across navigations because the configuration is held in a static or process-global field rather than scoped to the current navigation.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching session_management
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A WebView or HTTP-client component reuses request configuration (custom headers, cookies, auth token
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Shared Mutable State Leaks Session Cookie Across Loads | 1 | session_management | A WebView or HTTP-client component reuses request configuration (custom headers, | android, webview |

---

## DETECTION SIGNALS
**Positive signals:**
- A WebView or HTTP-client component reuses request configuration (custom headers, cookies, auth tokens) across navigations because the configuration is held in a static or process-global field rather than scoped to the current navigation.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Leaked session cookies grant the attacker full account takeover; the typical chain is to combine a navigation primitive (open-redirect or attacker-deeplink) with this leak to deliver the cookie to a controlled origin.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with info disclosure this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| csrf | Combined with info disclosure this typically extends impact through the csrf surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Lifetime / scope mismatch: configuration meant to be per-navigation was stored in process-global state, so a header bound to one origin's session is sent on the next navigation regardless of destination.
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
- **Impact statement:** Leaked session cookies grant the attacker full account takeover; the typical chain is to combine a navigation primitive (open-redirect or attacker-deeplink) with this leak to deliver the cookie to a controlled origin.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Lifetime / scope mismatch: configuration meant to be per-navigation was stored in process-global state, so a header bound to one origin's session is sent on the next navigation regardless of destination.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
