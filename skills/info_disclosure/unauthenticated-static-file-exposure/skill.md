# SKILL: INFO_DISCLOSURE — Unauthenticated Static File Exposure
**Category:** info_disclosure > unauthenticated-static-file-exposure
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The deployment bundle placed sensitive configuration alongside other static resources and the static-file handler served the directory without an access control layer, so files intended for operator-only access become a public surface.

---

## PRECONDITIONS
- [ ] Application serves static files from a directory whose contents include sensitive artifacts
- [ ] Sensitive values are stored in clear text rather than encrypted or referenced via a secret-management layer
- [ ] No authentication or authorization layer gates the static-file path

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: file_download. 

### Phase 2: Active Probing (Authorized Scope Only)
Enumerate the application's served path tree using a wordlist of common config / secret filenames (application config, environment files, license files, debug logs, installer artifacts). Make unauthenticated GET requests for each candidate path and inspect responses for credentials, API keys, internal hostnames, certificates, or other secrets. Pay attention to paths that are typically packaged with the deployable artifact (gateway, proxy, or appliance images often ship with example configs left in a publicly-served directory).

### Phase 3: Confirmation
Unauthenticated requests for predictable file paths under the application's web root return files containing credentials, configuration, license information, or other sensitive data in clear text.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching file_download
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: Unauthenticated requests for predictable file paths under the application's web root return files co
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Unauthenticated Static File Exposure | 1 | file_download | Unauthenticated requests for predictable file paths under the application's web | - |

---

## DETECTION SIGNALS
**Positive signals:**
- Unauthenticated requests for predictable file paths under the application's web root return files containing credentials, configuration, license information, or other sensitive data in clear text.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Credentials disclosed by this class commonly include service-account passwords or API tokens that unlock authenticated administrative paths, which themselves frequently expose code-execution surfaces.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with info disclosure this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| rce | Combined with info disclosure this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The deployment bundle placed sensitive configuration alongside other static resources and the static-file handler served the directory without an access control layer, so files intended for operator-only access become a public surface.
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
- **Impact statement:** Credentials disclosed by this class commonly include service-account passwords or API tokens that unlock authenticated administrative paths, which themselves frequently expose code-execution surfaces.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The deployment bundle placed sensitive configuration alongside other static resources and the static-file handler served the directory without an access control layer, so files intended for operator-only access become a public surface.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
