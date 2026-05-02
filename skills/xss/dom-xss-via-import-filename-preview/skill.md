# SKILL: XSS — Dom Xss Via Import Filename Preview
**Category:** xss > dom-xss-via-import-filename-preview
**Severity Range:** high
**Typical Payout:** $500
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
Filename-derived metadata was rendered into the DOM as HTML rather than as text, on the assumption that filenames are 'just text', so any markup smuggled into the filename executes in the previewer's session context.

---

## PRECONDITIONS
- [ ] Client-side code renders a user-supplied string into the DOM via an unescaping sink
- [ ] The user-supplied string can be set without sanitization on the upload / import path
- [ ] Some viewer of the preview shares the application origin and an authenticated session

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: import_function. 

### Phase 2: Active Probing (Authorized Scope Only)
On each import or upload feature, inspect how the client-side preview renders artifact metadata (filename, content-type, document title). Identify any property assigned via innerHTML, document.write, jQuery .html(), or similar non-escaping sink. Submit artifacts whose metadata contains HTML markers and observe whether the markup is parsed in the preview view. For features where the preview is shown to other users (shared imports, collaborative spaces), confirm whether one viewer's preview also reaches a victim's browser session — that determines the upgrade from self-XSS to one-click takeover. Probe the chain by triggering authenticated state-change requests (email change, token creation) from the preview-execution context.

### Phase 3: Confirmation
A preview UI rendered for a user-supplied artifact (filename, document title, paste content) executes script when the artifact's metadata contains markup, with no payload-bearing interaction other than viewing the preview.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching import_function
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A preview UI rendered for a user-supplied artifact (filename, document title, paste content) execute
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Dom Xss Via Import Filename Preview | 1 | import_function | A preview UI rendered for a user-supplied artifact (filename, document title, pa | - |

---

## DETECTION SIGNALS
**Positive signals:**
- A preview UI rendered for a user-supplied artifact (filename, document title, paste content) executes script when the artifact's metadata contains markup, with no payload-bearing interaction other than viewing the preview.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- DOM XSS in an authenticated preview composes naturally with same-origin state-change endpoints (email change, token issuance, account deletion) to escalate from script execution to full account takeover; this report is an instance of exactly that chain.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | Combined with xss this typically extends impact through the auth bypass surface | When the target is reachable from the same authentication context | medium |
| csrf | Combined with xss this typically extends impact through the csrf surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: Filename-derived metadata was rendered into the DOM as HTML rather than as text, on the assumption that filenames are 'just text', so any markup smuggled into the filename executes in the previewer's session context.
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
- **Impact statement:** DOM XSS in an authenticated preview composes naturally with same-origin state-change endpoints (email change, token issuance, account deletion) to escalate from script execution to full account takeover; this report is an instance of exactly that chain.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** Filename-derived metadata was rendered into the DOM as HTML rather than as text, on the assumption that filenames are 'just text', so any markup smuggled into the filename executes in the previewer's session context.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
