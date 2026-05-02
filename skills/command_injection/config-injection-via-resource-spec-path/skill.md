# SKILL: COMMAND_INJECTION — Config Injection Via Resource Spec Path
**Category:** command_injection > config-injection-via-resource-spec-path
**Severity Range:** high
**Typical Payout:** unknown
**Pattern Count:** 1
**Last Updated:** 2026-05-02
**Version:** 1.0.0

---

## OVERVIEW
The control-plane assumed declarative spec strings were 'just text' and templated them into another language without language-aware escaping; the trust boundary between user-specified resource fields and operator-generated configuration was missing.

---

## PRECONDITIONS
- [ ] A controller renders user-declared resource fields into a native configuration file
- [ ] Rendering does not escape the target config language's control characters
- [ ] Reload of the rendered config grants the attacker a privileged execution surface

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Surface candidates: admin_panel. Stack hints to filter for: kubernetes, nginx.

### Phase 2: Active Probing (Authorized Scope Only)
Identify control-plane components that translate declarative resource specs into native configuration files. For each user-supplied string in the spec, trace how it is templated into the rendered config and check whether the templater escapes characters that are syntactically meaningful in the target config language (semicolons, braces, quotes, newlines, include directives). Submit values containing those control characters and inspect the rendered configuration via the controller's introspection endpoint or by triggering a reload. Where the config language permits include of arbitrary files, look specifically at whether a write primitive elsewhere in the system can place an attacker-controlled file at an includable path.

### Phase 3: Confirmation
A user-controlled string in a resource specification (Ingress path, ConfigMap key, annotation value) is rendered into a generated configuration file (nginx.conf, haproxy.cfg, sshd_config) without escaping the syntactic control characters of that target language; the loaded configuration then contains attacker-supplied directives.

---

## TESTING WORKFLOW
```
Step 1: Identify endpoints matching admin_panel
   →
Step 2: Apply safe probe input derived from the documented detection approach
   →
Step 3: Observe response for the behavioral signal: A user-controlled string in a resource specification (Ingress path, ConfigMap key, annotation value)
   →
Step 4: Run a negative test with a baseline input to confirm the signal is specific to this class
   →
Step 5: Document the affected endpoint, the probe, the observed signal, and the impact estimate
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Config Injection Via Resource Spec Path | 1 | admin_panel | A user-controlled string in a resource specification (Ingress path, ConfigMap ke | kubernetes, nginx |

---

## DETECTION SIGNALS
**Positive signals:**
- A user-controlled string in a resource specification (Ingress path, ConfigMap key, annotation value) is rendered into a generated configuration file (nginx.conf, haproxy.cfg, sshd_config) without escaping the syntactic control characters of that target language; the loaded configuration then contains attacker-supplied directives.

**Negative signals (likely false positive):**
- Endpoint returns a generic error or 404 regardless of input — typical of a path that does not reach the suspected sink
- Response shape unchanged across probe and baseline — indicates the input does not influence the suspected sink

**Escalation signals:**
- Config injection in a process whose config controls request routing, file inclusion, or external-program invocation routinely escalates to RCE on the controller node and to unrestricted access to backend services.

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| rce | Combined with command injection this typically extends impact through the rce surface | When the target is reachable from the same authentication context | medium |
| info_disclosure | Combined with command injection this typically extends impact through the info disclosure surface | When the target is reachable from the same authentication context | medium |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The developer assumed: The control-plane assumed declarative spec strings were 'just text' and templated them into another language without language-aware escaping; the trust boundary between user-specified resource fields and operator-generated configuration was missing.
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
- **Impact statement:** Config injection in a process whose config controls request routing, file inclusion, or external-program invocation routinely escalates to RCE on the controller node and to unrestricted access to backend services.
- **CVSS hint:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Remediation:** The control-plane assumed declarative spec strings were 'just text' and templated them into another language without language-aware escaping; the trust boundary between user-specified resource fields and operator-generated configuration was missing.
- **PoC format:** Authenticated request capture, response capture showing the behavioral signal, and a screenshot or text comparison demonstrating the difference between probe and baseline.
