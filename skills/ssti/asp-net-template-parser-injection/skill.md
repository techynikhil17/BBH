# SKILL: SSTI — Asp Net Template Parser Injection
**Category:** ssti > asp-net-template-parser-injection
**Severity Range:** critical
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
User input was pasted into a string that the framework later treated as program source, so the template engine compiled and executed attacker-supplied code with the privileges of the host process.

---

## PRECONDITIONS
- [ ] Application invokes a server-side template parser on user-influenced markup at runtime
- [ ] Parser input is built by concatenation rather than a sandboxed binding model
- [ ] Template engine permits directive evaluation that reaches host-language constructs

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: report_generator. Stack hints to filter for: asp.net, sitecore.

### Phase 2: Active Probing (Authorized Scope Only)
Identify endpoints whose handler invokes a template parser at runtime — common indicators include `.ashx` handlers, dynamic Razor compilation, runtime `Page.ParseControl` calls, and any place where user input is concatenated into a markup string before parsing. Send minimal template syntax fragments (e.g., language-specific expression delimiters and harmless property accesses) and observe whether the response reflects the evaluated expression rather than the literal text. Once parsing is confirmed, escalate by testing whether the template engine exposes type instantiation, method invocation, or directive importation surfaces — these complete the chain to RCE.

### Phase 3: Confirmation
An endpoint that consumes a string later parsed as a server-side template (ASP.NET TemplateParser, Razor, ERB, Jinja2, Thymeleaf) executes attacker-controlled directives when the input contains template syntax — observable as evaluation of expressions, server-side property reads, or directive execution side effects.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching report_generator
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: An endpoint that consumes a string later parsed as a server-side template (ASP.NET TemplateParser, R
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Asp Net Template Parser Injection | 1 | report_generator | An endpoint that consumes a string later parsed as a server-side template (ASP.N | asp.net, sitecore |

---

## DETECTION SIGNALS
**Positive signals:**
- An endpoint that consumes a string later parsed as a server-side template (ASP.NET TemplateParser, Razor, ERB, Jinja2, Thymeleaf) executes attacker-controlled directives when the input contains template syntax — observable as evaluation of expressions, server-side property reads, or directive execution side effects.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Server-side template injection is one of the highest-leverage primitives in web applications: most enterprise template engines expose enough host-language surface that template execution upgrades to arbitrary code execution under the application identity.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| rce | Combined with ssti this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with ssti this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: User input was pasted into a string that the framework later treated as program source, so the template engine compiled and executed attacker-supplied code with the privileges of the host process.
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
- **Impact statement:** Server-side template injection is one of the highest-leverage primitives in web applications: most enterprise template engines expose enough host-language surface that template execution upgrades to arbitrary code execution under the application identity.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** User input was pasted into a string that the framework later treated as program source, so the template engine compiled and executed attacker-supplied code with the privileges of the host process.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
