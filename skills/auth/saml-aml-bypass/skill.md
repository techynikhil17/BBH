# SKILL: SAML Authentication Bypass — Signature & Parser Class
**Category:** auth_bypass > saml-signature-and-parser-bypass
**Severity Range:** high-critical
**Typical Payout:** $5,000–$50,000+ (auth bypass on enterprise SSO)
**Pattern Count:** 11
**Last Updated:** 2026-05-03
**Version:** 1.2.0
**Last analyzed against:** ruby-saml `3947ed7bd110a4b941ba1018bda9a1b61acc205e` (HEAD post-1.18.1)
**Spec basis:** OASIS SAML 2.0 Profiles `saml-profiles-2.0-os` (15 March 2005) §3.3, §4.1.4.2–§4.1.5, §4.4.3.4–§4.4.4.2

---

## OVERVIEW
SAML signs an XML assertion that the relying application trusts to identify the user. The bypass class exists because *signing* and *parsing* are two operations done at different times by different code, sometimes by different XML parsers, on a document the attacker fully controls — so any disagreement between "what was signed" and "what the app reads" lets an attacker change identity without breaking the cryptographic check. Developers miss it because the cryptographic primitives (`OpenSSL.verify`, `digest.matches?`) all return `true` for the genuinely-signed bytes; the bug is structural, not crypto-theoretical. In Ruby specifically, the use of two parsers (REXML and Nokogiri/libxml2) with different leniency creates a uniquely-rich differential surface.

---

## PRECONDITIONS
- [ ] Target Service Provider consumes SAML assertions from an external Identity Provider
- [ ] Library performs XML signature validation in application code (vs. only at the gateway)
- [ ] At least one of: (a) two XML parsers used in the same flow, (b) document re-serialized between parse and validate, (c) signature lookup by ID without uniqueness enforcement, (d) DOCTYPE accepted at any stage, (e) decryption substitutes content into a previously-parsed tree
- [ ] Validator returns boolean rather than raising — gives the attacker a useful failure-vs-success signal during probing
- [ ] (Optional but common) Target accepts both POST and Redirect bindings

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
SAML SPs expose a fixed set of endpoints worth mapping first:
- **ACS (Assertion Consumer Service)** — receives the signed `<samlp:Response>` after IdP login. POST binding usually; sometimes redirect.
- **SLO (Single Logout)** — receives `<samlp:LogoutRequest>` from IdP. Often less defended than ACS.
- **Metadata endpoint** — `/saml/metadata` or similar. Reveals supported bindings, certificates, NameID formats.
- **IdP-initiated endpoints** — sometimes a separate path that accepts an unsolicited Response.

For Ruby targets, fingerprint the library:
- `Server` headers and HTML often reveal Devise + omniauth-saml (which depends on ruby-saml)
- GitLab, Discourse, GoodData, JumpCloud, Workato all use ruby-saml or have used it historically
- Open-source repos: search `Gemfile.lock` for `ruby-saml` or `onelogin/ruby-saml`

### Phase 2: Active Probing (Authorized Scope Only)
**Source-first, not traffic-first.** For an open-source SP using ruby-saml, the highest-yield approach is reading the source code at the SP's pinned ruby-saml version, looking for the patterns enumerated under VULNERABLE CODE PATTERNS below. Probing live SAML flows requires a sandboxed IdP (mock-saml, SimpleSAMLphp test instance) you control — never craft assertions against an IdP you don't own.

When probing live (within program scope, against your own test tenant only):
- Capture a legitimate signed assertion from your own IdP test instance
- Mutate one structural element at a time (insert sibling element, duplicate ID, add comment, add DOCTYPE, swap signature scope)
- Compare SP behavior: 200 with session = bypass; 403 with descriptive error = signature still anchored; 500 = parser crash, possible DoS
- Out-of-band callbacks needed for XXE class only — sentinel domain via DNS

### Phase 3: Confirmation
A finding is real when:
- A *different* user identity (NameID, email) ends up in the SP's session than the one in the *signed* portion of the assertion
- Or: the SP accepts an assertion whose signature is invalid / mismatched / missing
- Or: the SP processes content from outside the signed scope (extension element, sibling Response)

False positives:
- Some libraries log "signature mismatch" but still create a session because of weak failure-mode handling — that's a real finding, but verify by checking session state, not just response body
- Mock IdPs often have lax fingerprint validation in test mode — confirm against staging/prod-like configuration

Escalation conditions:
- Bypass + admin NameID → critical
- Bypass tied to encrypted assertions only → still critical, narrower exposure
- Bypass requiring an IdP signing key → reduce to medium (key compromise has higher bar)

---

## TESTING WORKFLOW
```
Step 1: Identify SAML endpoints (ACS, SLO, metadata) on target SP
   →
Step 2: Identify SAML library + version (ruby-saml? omniauth-saml? Gemfile.lock)
   →
Step 3: Read library source at pinned version, mark each VULNERABLE CODE PATTERN
   →
Step 4: For each suspected pattern, design a structural mutation that exercises it
   →
Step 5: Generate a legitimate signed assertion via your own test IdP (never a real IdP)
   →
Step 6: Submit one mutation at a time to your own SP test instance, observe session state
   →
Step 7: Confirm finding by demonstrating an identity mismatch or unsigned-content trust
   →
Step 8: Document with paired pre-mutation / post-mutation requests, no working exploit
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Parser differential REXML↔Nokogiri | 4 | sso_flow | Validator and app see different `<ds:Signature>` / `<saml:Assertion>` | Ruby + ruby-saml; CVE-2025-25291/25292 |
| Permissive `//` XPath in signature flow | 3 | sso_flow | DigestValue accepted from `samlp:Extensions` outside signed scope | Ruby + ruby-saml; CVE-2024-45409 |
| DOCTYPE / `!ATTLIST` round-trip mutation | 2 | sso_flow | Document re-parses with mutated structure between validation passes | REXML pre-3.4.2 + libxml2 |
| libxml2 entity-ref XPath hash collision | 2 | sso_flow | Schema-validated original vs `at_xpath` on duplicate diverge | libxml2 / Nokogiri; CVE-2025-23369 |
| Encrypted-assertion signature substitution | 2 | sso_flow | First-extracted signature reused across pre/post-decrypt content | xmldsig + GHES; CVE-2024-9487/4985 |
| Classic XSW with duplicate ID elements | 5 | sso_flow | Signed element validated, sibling with same ID consumed | Cross-stack; OWASP XSW1–8 |
| Signature exclusion / fail-open | 3 | sso_flow, slo_flow | Validator returns true when signature absent | Cross-stack; ruby-saml SLO logout-request path |
| Token recipient/audience confusion | 1 | sso_flow | Assertion for SP-A accepted at SP-B | Cross-stack |
| XSLT injection via `<ds:Transform>` | 1 | sso_flow | Transform algorithm processes attacker-controlled XSLT | Cross-stack |
| XXE via SAML message | 1 | sso_flow | DOCTYPE entity expansion during parse | Default XML parsers |
| Certificate faking (fingerprint-only) | 1 | sso_flow | Self-signed cert with matching fingerprint accepted | Cross-stack |

---

## VULNERABLE CODE PATTERNS (Ruby / Nokogiri / libxml2)

### P1 — Mixed REXML and Nokogiri in the same signature flow
**What to grep for:**
```
REXML::XPath.first(   ... )
Nokogiri::XML(        ... )
document.at_xpath(    ... )
```
in the same source file, especially a signature-validation method.

**The bug shape:** signature element / SignatureValue / Reference URI / DigestValue extracted with one parser; canonicalization or hashed-element resolution done with the other. Each parser has its own view of the tree; an attacker constructs XML where the views disagree.

**Variant signal:** even after `safe_load_xml` was added in ruby-saml 1.18.0, look for *any* `REXML::Document.new(self.to_s)` inside the validation flow that re-parses without going through `safe_load_xml`. The 1.18.0 patch hardened the entry, not all the working copies.

### P2 — Permissive XPath axes in signature lookups
**What to grep for:**
```
"//ds:DigestValue"
"//ds:Signature"
"//*[@ID=$id]"
xpath(".//   ...")
```
without anchoring to the `<ds:Reference>` element.

**The bug shape:** an attacker plants a valid `<ds:DigestValue>` or `<ds:Signature>` in `<samlp:Extensions>` or any unsigned location; the `//` axis matches it; signature passes against attacker-supplied data.

**Fix shape:** XPath should be relative (`./ds:DigestValue`) and the result count should be enforced at exactly 1.

### P3 — DOCTYPE accepted by the entry parser
**What to grep for:**
```
Nokogiri::XML(input)                         # without STRICT/NONET options
REXML::Document.new(input)                   # REXML default behavior
```
without a `<!DOCTYPE` rejection check.

**The bug shape:** DOCTYPE enables `!ATTLIST` mutations that round-trip-mutate the document between validation and processing (PortSwigger SAML Roulette), and external entities for XXE.

**Fix shape:** wrap parsing in a helper like ruby-saml's `safe_load_xml` that rejects `<!DOCTYPE` and `internal_subset`, and uses `Nokogiri::XML::ParseOptions::STRICT | NONET`.

### P4 — Document duplication before XPath
**What to grep for:**
```
document.dup
.clone
Nokogiri::XML(document.to_s)
```
inside a method that previously schema-validated `document`.

**The bug shape:** libxml2's `xmlCopyDoc` does not duplicate entity declarations (CVE-2025-23369 / repzret). Schema validation runs against the original (entities present), XPath runs against the duplicate (entities resolved-or-missing differently). An entity-declared `ID` attribute may bypass uniqueness in one but match in the other.

**Fix shape:** parse with `Nokogiri::XML::ParseOptions::NOENT` to resolve entities up front, or never duplicate the validated document — operate on the original.

### P5 — Signature-validation short-circuit
**What to grep for:**
```ruby
def validate_signature
  return true if options.nil?
  return true unless options.has_key? :get_params
  return true unless options[:get_params].has_key? 'Signature'
  ...
end
```
**The bug shape:** when no signature is provided, return true. Caller treats the unsigned message as valid. Concrete instance: `ruby-saml` `SloLogoutrequest#validate_signature` — only validates HTTP-Redirect query-string signatures and silently accepts every other shape.

**Fix shape:** require a signature when configuration says it's required (`security[:want_assertions_signed]`, `security[:logout_requests_signed]`); raise or return false otherwise.

### P6 — First-occurrence signature/element selection
**What to grep for:**
```
sig_elements.first
reference_nodes[0]
at_xpath("...//ds:Signature")
```
without size enforcement.

**The bug shape:** when multiple `<ds:Signature>` or multiple elements with the same `ID` exist, only the first is checked, but the application may consume a later one. Classic XSW.

**Fix shape:** `sig_elements.size == 1` enforced; `reference_nodes.size == 1`; both as guard clauses before validation.

### P7 — Pre-decryption signature extraction (encrypted-assertion path)
**What to grep for:**
```
extract_signed_element
encrypted_assertion
decrypt_assertion
```
where the signature is captured before decryption substitutes plaintext into the document.

**The bug shape:** signature extracted from the original document binds to the *encrypted* element; decrypted plaintext replaces that element in a *duplicated* doc; subsequent validators check the duplicate and reuse the previously-extracted signature object. CVE-2024-9487 / 4985 is exactly this.

**Fix shape:** signature extraction must occur *after* decryption substitution, against the decrypted document, every time.

### P8 — Transform algorithm processed before signature validation
**What to grep for:**
```
process_transforms
ds:Transform
```
that `case`-matches algorithm strings.

**The bug shape:** XSLT or other transforms run before signature validation; transformed content is what's hashed. Transform-driven attacks alter what's "really" signed.

**Fix shape:** explicit allow-list of transform algorithms (c14n + enveloped-signature only); reject everything else.

### P9 — Certificate trust by fingerprint alone
**What to grep for:**
```
fingerprint == idp_cert_fingerprint
fingerprint_matches?
```
with no `OpenSSL::X509::Store` validation.

**The bug shape:** cert from inside the message is trusted because its fingerprint matches; but fingerprint is over the cert bytes, not over a trust chain. Attacker who controls *what cert is in the message* picks any cert whose fingerprint matches their target — usually requires a separate primitive, but combines with weak metadata fetch.

**Fix shape:** pin the *cert*, not the fingerprint, in settings; or validate against a trust store.

---

## RUBY-SAML SPECIFIC FINDINGS (HEAD 3947ed7, post-1.18.1)

The following variants were surfaced by reading `lib/xml_security.rb`, `lib/onelogin/ruby-saml/response.rb`, `lib/onelogin/ruby-saml/utils.rb`, and `lib/onelogin/ruby-saml/slo_logoutrequest.rb` against the patterns above. Status reflects what the current source does, not what the changelog claims.

### Confirmed live patterns (defense relies on neighboring controls)

- **F1 — Dual-parser flow remains in `cache_referenced_xml`.** `xml_security.rb:327` re-parses the document with `REXML::Document.new(self.to_s)` after `safe_load_xml` already loaded it via Nokogiri. Signature element (line 332), SignatureValue (347), and Reference (379) come from REXML; canonicalized SignedInfo (368) and hashed element (382) come from Nokogiri. The 1.18.0 fix narrowed the surface but did not remove the bridge.
- **F2 — Descendant-axis `//` XPath in signature lookups.** `xml_security.rb:246` and `:289` use `//ds:X509Certificate`; `:332` and `:365` use `//ds:Signature`; `:382` uses `//*[@ID=$id]`; `:487` uses `//ec:InclusiveNamespaces`. None are anchored to the signature being processed. The structural check in `response.rb:563–619` (`validate_signed_elements`) catches most XSW shapes that exploit this; SLO and metadata paths don't have that check.
- **F3 — `SloLogoutrequest` entry parse skips `safe_load_xml`.** `slo_logoutrequest.rb:47` `REXML::Document.new(@request)` accepts DOCTYPE, internal_subset, and malformed XML. Only the HTTP-Redirect query-string signature is validated; embedded XML signatures on POST-binding logout requests are silently accepted.
- **F4 — `validate_signature` fail-open in `SloLogoutrequest`.** `slo_logoutrequest.rb:278–285` returns `true` when `:get_params['Signature']` is absent. No code path exercises embedded XML signature validation for inbound logout requests. `is_valid?` returns true for forged unsigned LogoutRequests.
- **F5 — Decryption plaintext parsed via plain REXML.** `response.rb:1115` and `slo_logoutrequest.rb:112` both `REXML::Document.new(elem_plaintext)` on decryption output. DOCTYPE in decrypted plaintext reaches REXML directly. Attack requires decryption-oracle / CBC-malleability primitive on the encrypted blob — high precondition bar but no defense at this layer.
- **F6 — Greedy regex extracts decrypted assertion.** `response.rb:1110` `elem_plaintext.match(/(.*<\/(\w+:)?Assertion>)/m)[0]`. The `.*` is greedy with the `m` flag; it captures everything up to the *last* `</Assertion>`. If decryption produces extra content, that content is included in `elem_plaintext` and parsed.
- **F7 — `Marshal.load(Marshal.dump(document))` round-trip.** `response.rb:1040` round-trips a SignedDocument through Ruby Marshal, then `:1063` re-parses the modified doc via `XMLSecurity::SignedDocument.new(response_node.to_s)`. Three serialize/parse cycles exist between the original Response and the decrypted_document used for validation. The PortSwigger SAML Roulette research showed this class of round-trip mutation in REXML pre-3.4.2.
- **F8 — `entity_expansion_limit = 0`.** `xml_security.rb:38` sets the REXML class attribute to 0. In some REXML versions "0" means unlimited; in others "0" means no allowance. Worth verifying against the target's pinned Ruby version before claiming either way.
- **F9 — Cert lookup uses fingerprint-only trust.** `xml_security.rb:269` compares the cert-from-message's fingerprint against the configured fingerprint; no chain validation. Standard for SAML, but a probe target if the SP exposes its fingerprint config.

### Variants worth probing (V1–V10 from Step 4 analysis)

| ID | Variant | Affected file:line | Probe |
|---|---|---|---|
| V1 | REXML vs Nokogiri "first signature" disagreement | xml_security.rb:332 ↔ :365 | Construct signed XML where REXML's document order differs from Nokogiri's (namespace edge cases, comment placement) |
| V2 | Comment handling inside `<ds:SignedInfo>` between canonicalization and digest extraction | xml_security.rb:368 ↔ :419 | Add `<!-- -->` between SignedInfo children; compare REXML and Nokogiri trees |
| V3 | `SloLogoutrequest` entry-parse XXE/DOCTYPE | slo_logoutrequest.rb:47 | Send POST-binding LogoutRequest with `<!DOCTYPE` declaration; observe parser behavior |
| V4 | Post-decrypt REXML parse XXE | response.rb:1115 | Combine with decryption-oracle primitive (out of scope for this skill) |
| V5 | All entrypoints not behind `safe_load_xml` | F3, F5 above | grep targets for any `REXML::Document.new` or `Nokogiri::XML(` outside `safe_load_xml` callers |
| V6 | Multi-signature documents picking divergent "first" | xml_security.rb:332/365 | `validate_signed_elements` blocks count >= 3 and non-Response/Assertion parents — variants must satisfy these constraints |
| V7 | Duplicate-ID assertions outside signature scope | xml_security.rb:382, response.rb:994 | Plant `<saml:Assertion ID="signed-id">` outside `<samlp:Response>`; observe whether `signed_assertion` returns the planted or signed copy |
| V8 | Greedy regex post-decryption | response.rb:1110 | Decryption oracle that appends content past `</Assertion>` |
| V9 | `to_s` round-trip through REXML during decryption substitution | response.rb:1063 | SAML-Roulette `!ATTLIST` mutation; only relevant pre-Ruby-3.4.2 REXML |
| V10 | `doc_to_validate` switch happens after substitution | response.rb:850–867 | XSW shape that survives `validate_signed_elements` on `decrypted_document` |

### Confirmed closed at HEAD

- DOCTYPE rejection on Response/Logoutresponse entry (`xml_security.rb:52,64`)
- Strict-mode Nokogiri with `STRICT | NONET` (`:42`)
- DigestValue lookup is anchored: `./ds:DigestValue` relative to `@ref` (`:421`) — closes CVE-2024-45409 specifically
- XSLT/transform allow-list (`:442`)
- `validate_signed_elements` structural enforcement: signature-parent allow-list, ID uniqueness across signature targets, Reference URI matches parent ID, count < 3
- Audience and Destination validation present and called in validation chain

### SPEC-MANDATED VALIDATIONS (OASIS SAML 2.0 Profiles)

Each row is a normative MUST or MUST-NOT in the spec. Failure to enforce any of these is a vulnerability irrespective of crypto correctness.

| # | Spec § | Normative requirement | ruby-saml HEAD status | Probe / detection signal |
|---|---|---|---|---|
| S1 | §4.1.4.3 | SP MUST verify any signatures present on assertion(s) or response | Enforced by `Response.validate_signature` (response.rb:873). **Not enforced for `SloLogoutrequest`** (F4 above) | Submit POST-binding LogoutRequest with no XML signature; observe acceptance |
| S2 | §4.1.4.3 | SP MUST verify `Recipient` attribute on bearer `SubjectConfirmationData` matches the ACS URL the response was delivered to | Enforced in `validate_subject_confirmation` (response.rb:791) — bound by `:skip_recipient_check` option | Set `:skip_recipient_check => true` in consumer config: spec-violating but library-supported |
| S3 | §4.1.4.3 | SP MUST verify `NotOnOrAfter` on bearer SubjectConfirmationData has not passed (clock skew allowed) | Enforced (response.rb:814) | Submit assertion with NotOnOrAfter in past + delta within allowed_clock_drift |
| S4 | §4.1.4.3 | SP MUST verify `InResponseTo` matches the original AuthnRequest ID — OR for unsolicited responses MUST NOT be present | **Opt-in only** (response.rb:626–633): `validate_in_response_to` returns `true` if `:matches_request_id` option is not passed. The SP layer must actively pass the expected request ID; many integrations don't | Trace whether the SP code that calls `Response.is_valid?` plumbs `:matches_request_id`. If not, **InResponseTo is unchecked** — spec violation |
| S5 | §4.1.4.3 | Bearer `SubjectConfirmationData` MUST NOT contain `NotBefore` | Not explicitly rejected by ruby-saml (only `NotOnOrAfter` is parsed in subject confirmation context) | Probe target — submit assertion with NotBefore in bearer SubjectConfirmationData; check whether SP rejects |
| S6 | §4.1.4.2 | The assertion(s) containing a bearer subject confirmation MUST contain an `<AudienceRestriction>` including the SP's unique identifier as `<Audience>` | Enforced in `validate_audience` (response.rb:641) — bound by `:skip_audience` option and `settings.security[:strict_audience_validation]` | If `:skip_audience` is true OR `strict_audience_validation` is false and audiences is empty → audience check is skipped |
| S7 | §4.1.4.5 | If HTTP POST binding is used, the enclosed assertion(s) MUST be signed | ruby-saml exposes `settings.security[:want_assertions_signed]`; check is opt-in via that setting (response.rb:614) | If `want_assertions_signed` is false (default in older configs), an unsigned assertion may pass when only the Response is signed |
| S8 | §4.1.4.5 | **SP MUST ensure bearer assertions are not replayed**, by maintaining the set of used IDs for the NotOnOrAfter window | **NOT in ruby-saml core** — replay protection is the consumer's responsibility per ruby-saml documentation | Replay the same signed Response to the SP within the NotOnOrAfter window; if no consumer-layer dedup exists, replay succeeds |
| S9 | §4.1.5 | Unsolicited Response MUST NOT contain `InResponseTo`, nor should any bearer `SubjectConfirmationData` contain one | ruby-saml does not actively reject `InResponseTo` on responses where the consumer expected unsolicited; coupled with S4's opt-in, this is unchecked | Send Response with `InResponseTo="random"` to an unsolicited-flow endpoint; observe acceptance |
| S10 | §4.4.3.4 | LogoutResponse MUST be signed if HTTP POST or Redirect binding is used | `Logoutresponse#validate_signature` enforces (uses SignedDocument) | OK |
| S11 | §4.4.4.1 | LogoutRequest requester MUST authenticate itself, either by signing the message OR using a binding-specific mechanism | **Only Redirect-binding signature is checked**. POST-binding XML signatures are not validated by `SloLogoutrequest` (F4) | Submit POST-binding LogoutRequest unsigned or signed with attacker key; library accepts |
| S12 | §4.4.4.1 | LogoutRequest principal MUST be identified with an identifier matching the assertion identifier of the session being terminated, per [SAMLCore] §3.3.4 matching rules | Identifier is extracted but matching against the session's NameID is the consumer's responsibility | Probe: forged LogoutRequest with attacker-chosen NameID — does SP terminate the named user's session without checking NameID-to-current-session match? |

### Notable code-level grep patterns to use against ruby-saml-using SPs

```
# Find every parser entrypoint that does NOT go through safe_load_xml
grep -nE 'REXML::Document\.new|Nokogiri::XML\(' lib/ | grep -v safe_load_xml

# Find descendant-axis xpath in signature flow
grep -nE '"//ds:|"//\\*\\[@ID' lib/

# Find signature short-circuit returns
grep -nE 'def validate_signature' lib/ | xargs -I{} sh -c 'sed -n "/def validate_signature/,/^      end$/p" {}'

# Find regex-based plaintext extraction
grep -nE '\.match\(.*Assertion.*\)' lib/

# Find entity_expansion_limit configuration
grep -nE 'entity_expansion_limit' lib/
```

---

## DETECTION SIGNALS
**Positive signals:**
- Two parsers in same source file's signature flow
- `//` axis XPath in signature-related lookups
- Direct `Nokogiri::XML(...)` or `REXML::Document.new(...)` outside a `safe_load_xml`-style helper
- Signature validator returns `true` on absence
- `sig_elements.first` / `reference_nodes[0]` without size enforcement
- Document-duplication primitives between schema and XPath stages (`Marshal.dump`/`load`, `.dup`, `.clone`, `to_s` + re-parse)
- Decryption that substitutes content into a previously-parsed document

**Ruby-saml-specific positive signals (greppable):**
- `REXML::Document.new(self.to_s)` inside any method that already loaded the doc via `safe_load_xml`
- `REXML::Document.new(elem_plaintext)` after a decryption call
- `validate_signature` body containing `return true unless options.has_key? :get_params`
- `xpath("//*[@ID=$id]")` followed by `[0]` indexing without `size == 1` guard
- `entity_expansion_limit = 0` set on a BaseDocument subclass
- `REXML::XPath.first(self, "//ds:X509Certificate", ...)` in a signature-validation method (cert lookup not anchored to the signature being validated)
- Greedy regex `match(.*<\/(\w+:)?Assertion>)` with the multiline (`m`) flag

**Negative signals (likely false positive):**
- Single-parser flow (Nokogiri-only OR REXML-only end to end) on a strict parser
- Library that bails with `raise` on ambiguous signature shape
- All XPath relative-axis (`./`) and bounded by `count == 1`
- Allow-list of transform algorithms with explicit rejection branch

**Escalation signals:**
- Bypass yields admin NameID → critical
- Bypass works in encrypted-assertion mode (often less-tested code path)
- Same library used by multiple downstream products (ruby-saml is used by GitLab, Workato, Discourse, JumpCloud, etc.) — single bug, broad blast radius

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| auth_bypass | SAML bypass = direct authentication takeover | Whenever SP trusts SAML for session establishment | high |
| idor | Bypass to admin NameID + downstream IDOR = full tenant access | SP exposes per-tenant resources by ID | high |
| ssrf | XXE chain leaks internal network to attacker | DOCTYPE allowed + outbound DNS/HTTP from parser. **Note: not reachable in REXML — REXML never dereferences external entities. Applies only to libxml2/Nokogiri-based libraries with NOENT enabled.** | low (Ruby/REXML) — medium (other stacks) |
| info_disclosure | XXE → file read; debug error messages disclose key material | Verbose error mode in non-production deployments. **Note: REXML XXE-for-file-read closed; libxml2 still in scope** | low (Ruby/REXML) — medium (other stacks) |
| rce | XSLT transform abuse on permissive engines | Transform algorithm not allow-listed | low |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] "If `OpenSSL.verify` returns true, the assertion is authentic" — false: it confirms the *bytes* were signed, not that those bytes match what the app reads
- [ ] "REXML and Nokogiri see the same XML" — false: they have distinct leniency, namespace, comment, and DOCTYPE behavior; documented in the SAML Roulette / parser-differential research
- [ ] "Adding `safe_load_xml` to the entry parse closes the parser-differential class" — false: any later `REXML::Document.new(self.to_s)` re-parse re-opens it
- [ ] "Logout requests don't need signature validation; logging out is harmless" — false: forced logout is a CSRF-class primitive; if the SP issues a LogoutResponse with attacker-controlled destination, can chain further
- [ ] "Signature elements only appear in one place" — false: attackers can plant valid signatures inside `<ds:Object>`, `<samlp:Extensions>`, sibling responses, or wrapped assertions
- [ ] "Tests cover signature paths" — verify by reading the test suite. Ruby-saml's SLO logout-request signature test suite tests *only* HTTP-Redirect signatures, never embedded XML signatures

---

## SCOPE CHECKLIST
- [ ] Target's SAML implementation is open-source OR you have a sandboxed test SP
- [ ] You operate your own IdP for crafting test assertions — never use a real IdP
- [ ] Probes are sent only to your own test SP / staging tenant
- [ ] No real user identities are impersonated in the probe
- [ ] OOB infrastructure (DNS sentinel) ready for XXE probes
- [ ] Stop and rotate test credentials at any sign of unintended access

---

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|
| 2026-05-03 | ruby-bbh-r1 | F4: SloLogoutrequest `validate_signature` is fail-open for POST-binding inbound logout requests | medium (forced-logout primitive; chains with SP logout-response open redirect) | yes — see RUBY-SAML SPECIFIC FINDINGS F4 |
| 2026-05-03 | ruby-bbh-r1 | F3: SloLogoutrequest entry-parse `REXML::Document.new(@request)` skips `safe_load_xml`; DOCTYPE / internal_subset / malformed-XML accepted | medium (XXE preconditions depend on REXML version) | yes — F3 |
| 2026-05-03 | ruby-bbh-r1 | F1: dual-parser bridge in `cache_referenced_xml` survives the 1.18.0 fix — REXML re-parse at xml_security.rb:327 | high if a working REXML/Nokogiri differential is found | yes — F1 + V1/V2 |
| 2026-05-03 | ruby-bbh-r1 | F6: greedy regex `(.*</Assertion>)/m` over decrypted plaintext could capture trailing content | medium (requires decryption-oracle primitive) | yes — F6 + V8 |
| 2026-05-03 | ruby-bbh-r1 | F8: `REXML::Document::entity_expansion_limit = 0` — semantics version-dependent | low/medium (DoS) | yes — F8 |
| 2026-05-03 | ruby-bbh-r1 | S4: ruby-saml `validate_in_response_to` is opt-in via `:matches_request_id`; spec violation if SP integration doesn't pass it | high (assertion replay across sessions; chains with S8 replay) | yes — SPEC-MANDATED VALIDATIONS S4 |
| 2026-05-03 | ruby-bbh-r1 | S8: ruby-saml has no consumer-layer replay protection for bearer assertions; spec MUST is delegated to the consumer | high (assertion replay primitive) | yes — S8 |
| 2026-05-03 | ruby-bbh-r1 | S5: bearer SubjectConfirmationData with `NotBefore` not explicitly rejected (spec MUST NOT) | low (parser edge) | yes — S5 |
| 2026-05-03 | ruby-bbh-r1 | S9: unsolicited-response `InResponseTo` presence not actively rejected | medium | yes — S9 |
| 2026-05-03 | ruby-bbh-r1 | S12: LogoutRequest NameID-to-current-session matching is consumer's responsibility; combined with F4 = forged-logout primitive | medium (forced logout of arbitrary user by NameID) | yes — S12 |
| 2026-05-03 | ruby-bbh-r2 | F8 resolved: in REXML 3.4.x `limit=0` strictly disallows any entity expansion (raises on count > 0). Setter goes through `REXML::Security` class variable, so the hardening is **process-global** — affects every REXML::Document in the process, not just XMLSecurity::BaseDocument subclasses. | n/a — closes a hypothesis | yes — FAILED APPROACHES |
| 2026-05-03 | ruby-bbh-r2 | REXML never dereferences external entities (no Net::HTTP / URI.open / File.open in entity-resolution path). Classic XXE-for-SSRF / XXE-for-file-read structurally impossible in REXML across all currently-supported Ruby versions (3.3, 3.4, 4.0; 3.2 EOL 2026-03-31). | n/a — closes a hypothesis | yes — FAILED APPROACHES |
| 2026-05-03 | ruby-bbh-r2 | LogoutResponse `Destination` derived from `settings.idp_slo_response_service_url` (slo_logoutresponse.rb:121), NOT from the inbound LogoutRequest. Forced-logout primitive (F4) cannot be chained into an open redirect via this path. | n/a — closes a chain hypothesis | yes — FAILED APPROACHES + chain table downgrade |
| 2026-05-03 | ruby-bbh-r3 | **Naive URI parsing in `extract_signed_element_id` (xml_security.rb:482)** — `reference_element.attribute("URI").value[1..-1]` blindly strips first character without verifying it's `#`. Edge cases mapped: `URI=""` → nil → falls through to `Reference.parent.parent.parent.attribute("ID").value` (3 fixed levels up = expected enveloped Signature parent); `URI="abc"` (no #) → "bc" → looks up wrong ID → no match → validation fails closed; `URI="#"` → "" → no match → fails closed. None of these enable bypass — Nokogiri xpath at line 382 returns empty and `hashed_element.nil?` short-circuits. Code smell, not a bug. | low — code quality | yes — see "VULNERABLE CODE PATTERNS" extension below |
| 2026-05-03 | ruby-bbh-r3 | **All identity-bearing extractors are properly scoped to `signed_assertion`** — name_id, name_id_format, attributes, sessionindex, conditions, not_before, not_on_or_after, audiences, session_expires_at, and Assertion Issuer all route through `xpath_first_from_signed_assertion` / `xpath_from_signed_assertion` (response.rb:1003/1018). The `signed_assertion` is built from `referenced_xml` (the Nokogiri-canonicalized bytes of the signed element, which is what was hash-matched). Subsequent REXML XPath inside that scope cannot escape the signed bytes. | n/a — confirms defense | yes — V6/V7/V10 closed in FAILED APPROACHES |
| 2026-05-03 | ruby-bbh-r3 | **By-design unsigned outer-Response extractors:** `destination` (response.rb:344), `in_response_to` (331), `status_code` (237), `status_message` (260), and Response-level `Issuer` (307) all read from the original unsigned `document`. SAML 2.0 only requires the Assertion (or whole Response) to be signed; the outer-Response wrapper is commonly unsigned. **Residual concern:** in IdP-initiated SSO with `validate_in_response_to` disabled, an attacker who captures any signed Assertion can wrap it in their own Response with attacker-chosen `Destination` matching the SP's ACS — this is SAML Assertion Replay, the canonical class. ruby-saml's `validate_audience` and `validate_in_response_to` are the configured defenses; if either is disabled in the SP's settings, replay is reachable. | medium — depends on SP config; not a ruby-saml-side bug | yes — see ASSUMPTIONS TO CHALLENGE |

---

## ATTACK CHAINS DISCOVERED


---

## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|
| **V1 — REXML vs Nokogiri "first signature" disagreement (xml_security.rb:332 ↔ :365)** Expected: a doc construct where REXML's `//ds:Signature` first-match differs from Nokogiri's `at_xpath('//ds:Signature')`. Actual: both parsers operate on `self.to_s` (REXML's serialization). `safe_load_xml` already rejected DOCTYPE / malformed XML on the Nokogiri side, so by the time the bridge happens both parsers see well-formed serialized REXML output. `validate_signed_elements` (response.rb:563–610) further enforces `signature_nodes.length < 3`, parent must be Response or Assertion, IDs unique across signed parents, and Reference URI must match parent ID. No XML construct found that gives REXML and Nokogiri divergent first-signature views past those gates. | 2026-05-03 | ruby-bbh-r3 |
| **V2 — Comment handling between canonicalization and digest extraction (xml_security.rb:368 ↔ :419)** Expected: comments inside `<ds:SignedInfo>` cause Nokogiri's canonicalize output to diverge from REXML's view of the SignedInfo subtree. Actual: Canonical XML (C14N 1.0/1.1) **strips comments** unless the explicit `WithComments` algorithm is selected — both parsers produce comment-stripped output. The transform allow-list at xml_security.rb:442 maps `c14n` and `xml-exc-c14n#` to comment-stripping variants by default. No reachable comment-divergence variant. | 2026-05-03 | ruby-bbh-r3 |
| **V6 — Multi-signature divergent "first" pick (xml_security.rb:332/365)** Expected: a doc with 2+ signatures where REXML picks one as "first" and Nokogiri picks the other; the canonicalized SignedInfo verifies but the application consumes the wrong assertion. Actual: `validate_signed_elements` enforces `signature_nodes.length < 3` (response.rb:609). A document with 3+ signatures is rejected outright. With at most 2 signatures (Response + Assertion), every signature is independently structurally validated, and `cache_referenced_xml` validates whichever one the bridge picks first. No room for divergent-pick exploitation that survives the structural check. | 2026-05-03 | ruby-bbh-r3 |
| **V7 — Duplicate-ID assertions outside signature scope (response.rb:994 / xml_security.rb:382)** Expected: plant `<saml:Assertion ID="signed-id">` outside the signed Response so REXML's `signed_assertion` extraction picks the planted copy instead of the signed one. Actual: `validate_num_assertion` (response.rb:512–540) enforces exactly 1 Assertion in the outer document AND exactly 1 in the decrypted document. `validate_signed_elements` (response.rb:584–587) rejects duplicate IDs across signed parents. `get_cached_signed_assertion` (response.rb:968) re-parses `referenced_xml` (the Nokogiri C14N output of the signed element) — which is the validated bytes by definition; whatever REXML extracts from those bytes was inside the cryptographically authenticated scope. Duplicate-ID injection blocked at multiple layers. | 2026-05-03 | ruby-bbh-r3 |
| **V10 — Extractor reads on `@decrypted_document` outside signed scope** Expected: an attribute or assertion extractor calls `REXML::XPath.first` on `@decrypted_document` (or `@document`) directly, returning content that wasn't inside the signed referenced_xml. Actual: identity-bearing extractors (`name_id`, `name_id_format`, `attributes`, `sessionindex`, `conditions`, `not_before`, `not_on_or_after`, `audiences`, `session_expires_at`, Assertion `Issuer`) all go through `xpath_first_from_signed_assertion` / `xpath_from_signed_assertion` (response.rb:1003 + 1018), which root XPath on `signed_assertion` (the cached REXML re-parse of `referenced_xml`). The outer-document extractors that DO bypass the signed cache — `destination` (344), `in_response_to` (331), `status_code` (237), `status_message` (260), Response `Issuer` (305) — are reading attributes of the unsigned outer `<samlp:Response>` element by SAML 2.0 spec; that's not a bug, it's the protocol. See note below for the one residual concern. | 2026-05-03 | ruby-bbh-r3 |
| **XXE via DOCTYPE in SloLogoutrequest entry parse (V3)** — Expected: a POST-binding LogoutRequest with a DOCTYPE declaration containing an external-SYSTEM entity reference (file or network URL) reaches the unsafe REXML parse and dereferences the resource for file-read or SSRF on REXML 3.4.x (currently-supported Ruby 3.3/3.4/4.0; Ruby 3.2 EOL 2026-03-31). | REXML never fetches external entities at all — `grep -rn 'open-uri\|Net::HTTP\|URI.open\|File.open\|IO.read' lib/` against REXML source returns only a docstring example. External entity declarations are stored as `@external = "SYSTEM"` strings, never dereferenced (see `entity.rb:36-46`). Classic XXE for file-read or SSRF is structurally not possible in REXML, regardless of Ruby version. | 2026-05-03 | ruby-bbh-r2 |
| **Billion-laughs / entity expansion DoS via SloLogoutrequest** | `xml_security.rb:38` sets `REXML::Document::entity_expansion_limit = 0` at file-load time. This delegates to `REXML::Security.entity_expansion_limit = 0`, a class variable on the `Security` module — **process-global**. Every `REXML::Document.new` created after `xml_security.rb` is loaded (which is the require-graph entry for any ruby-saml use, including SloLogoutrequest via `saml_message.rb`) inherits limit=0. `record_entity_expansion` raises on the first count > 0 → first entity reference aborts the parse. F8's "0 means unlimited or 0?" question is resolved: in REXML 3.4.x it means **strictly zero allowed**. | 2026-05-03 | ruby-bbh-r2 |
| **Open redirect via LogoutResponse destination derived from forged LogoutRequest** — chaining F4 (logout fail-open) into a redirect to attacker-controlled URL | `slo_logoutresponse.rb:121` reads `destination = settings.idp_slo_response_service_url \|\| settings.idp_slo_service_url`. The destination is taken from the SP's **configured settings**, never from the inbound LogoutRequest. `SloLogoutrequest` exposes no Destination/ResponseLocation extractor. An attacker who fakes a LogoutRequest cannot influence where the LogoutResponse is sent. F4's chain hypothesis to open-redirect is therefore dead via this path. | 2026-05-03 | ruby-bbh-r2 |

---

## REPORTING TEMPLATE HINTS
- **Impact statement:** Authentication bypass: an unauthenticated attacker can impersonate any user (or any admin) by submitting a crafted SAML response that the relying party validates as authentic but whose user-identifying content the application reads from outside the signed scope.
- **CVSS hint:** AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N (network, attack-complexity high reflects the XML construction; scope-changed because crossing the auth boundary)
- **Remediation:** Apply the relevant CVE patch (1.18.0+ for ruby-saml). Beyond the patch, mandate single-parser flows, anchor all XPath in signature paths, enforce size==1 on signature/reference lookups, reject DOCTYPE at the boundary, perform signature extraction *after* decryption substitution, and require signatures (not just validate them when present).
- **PoC format:** Two saved HTTP requests — the legitimate signed assertion and the structurally-mutated assertion — and a screenshot or session-state capture showing identity divergence between the *signed* identity and the *session* identity. No working exploit code; methodology only.
