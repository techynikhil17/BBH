# SKILL: INFO_DISCLOSURE — Firebase Credentials In Client Bundle
**Category:** info_disclosure > firebase-credentials-in-client-bundle
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Developers treated the Firebase web SDK config as a public identifier (which it technically is) and assumed the security rules layer would prevent abuse. The security rules were not actually tightened in production — defaulting to allow-read-or-allow-write on broad paths during development and never being narrowed before launch.

---

## PRECONDITIONS
- [ ] Application uses Firebase (Realtime Database, Firestore, or Storage) on the client side
- [ ] Firebase configuration is shipped to the browser as static JavaScript
- [ ] Firebase security rules permit unauthenticated, or weakly-scoped, read or write operations on at least one path that contains business data

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: api_endpoint. Stack hints to filter for: firebase, gcp, javascript.

### Phase 2: Active Probing (Authorized Scope Only)
Pull the production JavaScript bundles (main.js, vendor.js, env.js) and grep the source for Firebase-config shapes — apiKey, authDomain, databaseURL, projectId, storageBucket, messagingSenderId, appId. When a config is found, attempt to instantiate a Firebase client with those credentials in a controlled environment and probe the database / Firestore root with a read query. Inspect the response for permission-denied vs allowed semantics. Where reads succeed, attempt a benign write to a non-production-looking path to determine whether the security rules are also write-permissive. Never read or modify real user data; treat any access to non-test paths as escalation-required and stop.

### Phase 3: Confirmation
Firebase API keys, project IDs, and database URLs are statically embedded in the front-end JavaScript bundle, AND the corresponding Firebase Realtime Database / Firestore security rules are permissive enough to allow direct client-side read or write operations without authenticated session checks.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching api_endpoint
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: Firebase API keys, project IDs, and database URLs are statically embedded in the front-end JavaScrip
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Firebase Credentials In Client Bundle | 1 | api_endpoint | Firebase API keys, project IDs, and database URLs are statically embedded in the | firebase, gcp, javascript |

---

## DETECTION SIGNALS
**Positive signals:**
- Firebase API keys, project IDs, and database URLs are statically embedded in the front-end JavaScript bundle, AND the corresponding Firebase Realtime Database / Firestore security rules are permissive enough to allow direct client-side read or write operations without authenticated session checks.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Direct database read access against a permissive Firebase rule set bypasses every server-side authorization layer the application has. From there an attacker can enumerate user records (mass IDOR), exfiltrate PII (info disclosure), or — if write rules are also loose — modify role/permission documents to take over privileged accounts (auth bypass / privesc).

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with info disclosure this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| idor | Combined with info disclosure this typically extends impact through the idor surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with info disclosure this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Developers treated the Firebase web SDK config as a public identifier (which it technically is) and assumed the security rules layer would prevent abuse. The security rules were not actually tightened in production — defaulting to allow-read-or-allow-write on broad paths during development and never being narrowed before launch.
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
- **Impact statement:** Direct database read access against a permissive Firebase rule set bypasses every server-side authorization layer the application has. From there an attacker can enumerate user records (mass IDOR), exfiltrate PII (info disclosure), or — if write rules are also loose — modify role/permission documents to take over privileged accounts (auth bypass / privesc).
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Developers treated the Firebase web SDK config as a public identifier (which it technically is) and assumed the security rules layer would prevent abuse. The security rules were not actually tightened in production — defaulting to allow-read-or-allow-write on broad paths during development and never being narrowed before launch.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
