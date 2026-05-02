# SKILL: AUTH_BYPASS — 2Fa State Overwrite
**Category:** auth_bypass > 2fa-state-overwrite
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Developer treated the multi-step auth state as a sequence of independent flag updates rather than as a chain of cryptographically-bound assertions. The 2FA gate read a session-state flag that was writable by other endpoints, instead of verifying the user had presented the actual second factor in the current authentication context.

---

## PRECONDITIONS
- [ ] Application uses multi-step authentication where intermediate state is persisted server-side or in cookies between the password step and the 2FA step
- [ ] An endpoint exists that can update the relevant authentication-state flag without re-checking the 2FA factor
- [ ] The 2FA gate trusts the state flag rather than re-deriving completion from cryptographic evidence (e.g., an HMAC over the OTP)

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: auth_endpoint. 

### Phase 2: Active Probing (Authorized Scope Only)
Map the multi-step authentication flow end-to-end: identify each request the client sends between password submission and the protected resource, including any session, cookie, or server-side state mutated along the way. Look for endpoints that update authentication-state-relevant flags (mfa_completed, auth_step, factor_status) and that can be reached while the session is in the partial-auth state. Test whether replaying a state-change request from a fully-authenticated session, or directly invoking the state-update endpoint with crafted parameters, advances the partial session past the 2FA gate. Also verify whether server-side state and client-side cookies must agree, or whether one alone is consulted.

### Phase 3: Confirmation
After completing a partial authentication step (password verified, 2FA pending), submitting a separate state-changing request alters the server-tracked authentication state in a way that lets the user proceed past the 2FA gate without supplying the second factor.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching auth_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: After completing a partial authentication step (password verified, 2FA pending), submitting a separa
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| 2Fa State Overwrite | 1 | auth_endpoint | After completing a partial authentication step (password verified, 2FA pending), | - |

---

## DETECTION SIGNALS
**Positive signals:**
- After completing a partial authentication step (password verified, 2FA pending), submitting a separate state-changing request alters the server-tracked authentication state in a way that lets the user proceed past the 2FA gate without supplying the second factor.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- A 2FA bypass directly enables account takeover; once authenticated as the victim, all per-user IDOR and info disclosure surfaces become accessible at maximum impact.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| idor | Combined with auth bypass this typically extends impact through the idor surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with auth bypass this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Developer treated the multi-step auth state as a sequence of independent flag updates rather than as a chain of cryptographically-bound assertions. The 2FA gate read a session-state flag that was writable by other endpoints, instead of verifying the user had presented the actual second factor in the current authentication context.
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
- **Impact statement:** A 2FA bypass directly enables account takeover; once authenticated as the victim, all per-user IDOR and info disclosure surfaces become accessible at maximum impact.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Developer treated the multi-step auth state as a sequence of independent flag updates rather than as a chain of cryptographically-bound assertions. The 2FA gate read a session-state flag that was writable by other endpoints, instead of verifying the user had presented the actual second factor in the current authentication context.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
