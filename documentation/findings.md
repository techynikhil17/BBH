# Findings — SAML / OAuth Authentication Research

Living index of every finding investigated across sessions. Per-bug deep dives live in companion files in this directory.

## DO NOT DUPLICATE — Known GitLab SAML CVEs (per gitlab-org/cves @ master, May 2026)

Any finding we surface must be checked against this list. If it overlaps, the finding is already known.

| CVE | Year | CWE | Class | Versions Fixed In | Reporter |
|---|---|---|---|---|---|
| CVE-2022-1162 | 2022 | Hardcoded password | OmniAuth-provisioned accounts (SAML/LDAP/OAuth) given hardcoded password → ATO | 14.7.7 / 14.8.5 / 14.9.2 | internal |
| CVE-2022-1680 | 2022 | SCIM ATO | Group SAML SSO + SCIM: Premium-tier owner invites arbitrary user, changes their email via SCIM, takes over | 14.9.5 / 14.10.4 / 15.0.1 | internal |
| CVE-2022-4331 | 2022 | Authorization | Removed maintainer/owner retains access after group transferred to new namespace | 15.7.8 / 15.8.4 / 15.9.2 | external |
| CVE-2023-1965 | 2023 | RelayState CSRF | RelayState parameter not validated → 3rd-party Group SAML SSO access tokens leaked to attacker URL | 15.9.6 / 15.10.5 / 15.11.1 | bull (H1 #1923672) |
| CVE-2024-4597 | 2024 | CSRF | Active-SAML-session user can be forced to approve an MR via CSRF (CWE-352, not a SAML protocol bug) | 16.9.7 / 16.10.5 / 16.11.2 | joernchen (internal) |
| **CVE-2024-12093** ⚠️ | **2024** | **CWE-1288 Improper Validation of Consistency** | **"Improper XPath validation allows modified SAML response to bypass 2FA requirement under specialized conditions"** — XPath-handling family | **17.10.7 / 17.11.3 / 18.0.1** | joaxcar (H1 #2851261) |
| CVE-2024-13041 | 2024 | CWE-286 Incorrect User Management | external_groups overrides external_provider → user not marked external → access to internal projects | 17.5.5 / 17.6.3 / 17.7.1 | dblessing (internal) |
| CVE-2025-1540 | 2025 | CWE-863 Incorrect Authorization | External user can read/clone internal projects (SAML auth misconfigures external attribute) | 17.6.5 / 17.7.4 / 17.8.2 | external |
| CVE-2025-2256 | 2025 | CWE-1284 DoS | Multiple concurrent large SAML responses → instance unresponsive | 18.1.6 / 18.2.6 / 18.3.2 | yuki_osaki, lambdasawa (H1 #3019485) |

**Implications for this session:**
- ⚠️ **CVE-2024-12093 is the closest analog to our F2 (descendant-axis XPath in signature lookups) hypothesis.** The XPath-modified-response 2FA-bypass pattern was patched in 17.10.7+. Variants of THIS pattern are unlikely to still exist; the maintainers had eyes on it recently.
- CVE-2025-2256 closes the "huge SAML response DoS" angle — already known.
- CVE-2024-13041 + CVE-2025-1540 close two "SAML configuration / external-user" bugs — pattern is known.
- The application-layer surface that has paid out: RelayState (CVE-2023-1965), SCIM/SAML interaction (CVE-2022-1680), authorization-logic gaps (CVE-2024-13041, CVE-2025-1540). Less paid out: the protocol-level signature/XPath stuff (CVE-2024-12093 fixed once and likely well-reviewed).

**HackerOne search results (May 2026):**
- 0 disclosed reports matching "SAML InResponseTo"
- 1 canonical report on the SAML login CSRF class: H1 #171398 (2016, accepted-as-design)
- H1 #888930 (SAML response replay): accepted-as-mitigated by NotOnOrAfter
- H1 #1923672 (CVE-2023-1965 RelayState): paid

**GitHub Security Advisories (May 2026):**
- omniauth-saml: 3 advisories — none on InResponseTo / login CSRF
- ruby-saml: 7 advisories — none on InResponseTo / login CSRF; all signature/parser/DoS class

## SUMMARY TABLE

| ID | Title | Status | Severity | Date |
|----|-------|--------|----------|------|
| RS-F1 | ruby-saml: dual-parser flow remains in `cache_referenced_xml` | Candidate | High (if differential found) | 2026-05-03 |
| RS-F2 | ruby-saml: descendant-axis `//` XPath in signature lookups | Candidate (mitigated by validate_signed_elements) | Medium | 2026-05-03 |
| RS-F3 | ruby-saml: `SloLogoutrequest` entry parse skips `safe_load_xml` | Confirmed (defect; reachability narrow) | Medium | 2026-05-03 |
| RS-F4 | ruby-saml: `validate_signature` fail-open for POST-binding LogoutRequest | Confirmed (defect; consumer-dependent reachability) | Medium | 2026-05-03 |
| RS-F5 | ruby-saml: decryption plaintext parsed via plain REXML | Candidate (chains with C2) | Medium-High | 2026-05-03 |
| RS-F6 | ruby-saml: greedy regex extracts decrypted assertion | Candidate (chains with C2) | Medium-High | 2026-05-03 |
| RS-F7 | ruby-saml: `Marshal.dump/load` round-trip on SignedDocument | Candidate (research-vehicle) | Low (alone) | 2026-05-03 |
| RS-F8 | ruby-saml: `entity_expansion_limit = 0` semantics | Ruled Out | Informational | 2026-05-03 |
| RS-F9 | ruby-saml: cert lookup uses fingerprint-only trust | By-design | Informational | 2026-05-03 |
| RS-F10 | ruby-saml: `decrypt_element` regex NoMethodError as binary oracle | Confirmed (oracle source); end-to-end requires SP error distinguishability | High (if SP leaks error states) | 2026-05-03 |
| RS-F11 | ruby-saml: CBC modes accepted for assertion content (no GCM-only enforcement) | Confirmed | High | 2026-05-03 |
| RS-F12 | ruby-saml: RSA-1_5 accepted for symmetric-key unwrap (Bleichenbacher target) | Confirmed | High | 2026-05-03 |
| RS-F13 | ruby-saml: `cipher.padding = 0` disables PKCS#7 padding validation | Confirmed | High (amplifies F10) | 2026-05-03 |
| C2 | Chain: CBC chosen-ciphertext + greedy regex + REXML re-parse → assertion content substitution | Candidate (theoretical chain) | Critical-if-exploitable | 2026-05-03 |
| C2-GL | Chain C2 reachability against GitLab default config | **Ruled Out** — GitLab SAML docs default `want_assertions_encrypted: false`; no XMLEnc decryption step to oracle | N/A on default GitLab; remains relevant for SPs that DO require encrypted assertions | 2026-05-04 |
| GL-1 | GitLab SAML sign-in flow does not enforce `InResponseTo` (login CSRF class) | Candidate; class publicly known since 2016 (HackerOne #171398) accepted-as-design at multiple SPs | Medium | 2026-05-04 |
| GL-2 | GitLab Instance SAML: `admin`/`auditor` flag set directly from SAML `groups` attribute on every login | Confirmed — by-design but is the impact endpoint for any signature-bypass primitive | Critical-if-chained-with-signature-bypass | 2026-05-04 |
| GL-3 | GitLab Group SAML: `set_attributes_for_enterprise_user!` mass-assigns `auth_hash.user_attributes` to managed users | Bounded today (only `can_create_group`, `projects_limit`); future extensions need review | Low (today); High (if ALLOWED_USER_ATTRIBUTES extended carelessly) | 2026-05-04 |
| GL-4 | Group SAML sign-in flow has identical `OriginValidator` gap as instance SAML | Confirmed — same shape as GL-1, independent attack surface | Medium | 2026-05-04 |
| GL-5 | Group SAML `RelayState` only honored when `valid_gitlab_initiated_saml_request?` (post-CVE-2023-1965) | Confirmed closed | N/A | 2026-05-04 |
| DK-1 | doorkeeper: token revocation bypass for public clients | Already fixed upstream (commit `ecc1599`, March 2026) | N/A | 2026-05-04 |
| DK-2 | doorkeeper: variant analysis of `confidential?` gating | Ruled Out — no exploitable variant in introspection / authcode / refresh paths | N/A | 2026-05-04 |
| DK-3 | doorkeeper: `validate_client_match` returns true for `application_id.blank?` refresh tokens | Ruled Out — consistent with by-design ownerless-token model | Informational | 2026-05-04 |

---

### [RS-F1] ruby-saml: dual-parser flow remains in `cache_referenced_xml`
**Date:** 2026-05-03
**Status:** Candidate
**Severity:** High (if a working differential is constructed)

#### What Was It
ruby-saml's `XMLSecurity::SignedDocument#cache_referenced_xml` (lib/xml_security.rb:314-396) loads the document with both Nokogiri (via `safe_load_xml`) and REXML (via `REXML::Document.new(self.to_s)` at line 327). Signature element / SignatureValue / Reference / DigestValue are extracted via REXML; canonicalized SignedInfo bytes and the hashed referenced element come from Nokogiri. CVE-2025-25291/25292 fix narrowed but did not close this bridge.

#### How We Found It
Read `xml_security.rb` end-to-end against published research (PortSwigger SAML Roulette, repzret libxml2 quirks, github.blog parser-differential). The 1.18.0 fix added `safe_load_xml` for the entry parse but kept the REXML re-parse for the working_copy and the signed_info string round-trip.

#### Impact
If a researcher constructs an XML document the two parsers see differently and that survives `validate_signed_elements`, the result is signature bypass — authenticate as any user. Same impact ceiling as CVE-2025-25291.

#### Evidence
- lib/xml_security.rb:319 — `safe_load_xml` (Nokogiri, strict)
- lib/xml_security.rb:327 — `@working_copy ||= REXML::Document.new(self.to_s).root` (REXML, no checks)
- lib/xml_security.rb:332 — REXML `//ds:Signature` lookup
- lib/xml_security.rb:365 — Nokogiri `at_xpath('//ds:Signature')` lookup
- lib/xml_security.rb:382 — Nokogiri `xpath("//*[@ID=$id]")[0]` (no uniqueness check)

#### Why It Was Ruled Out (if applicable)
N/A — not ruled out. Construction of a working differential is the open question.

#### Next Steps / Open Questions
Variants V1, V2, V6 in the skill catalog. Strict-mode Nokogiri narrows the search space dramatically but doesn't close it. A test bench with paired Nokogiri+REXML diagnostic output is the right tool.

---

### [RS-F3] ruby-saml: `SloLogoutrequest` entry parse skips `safe_load_xml`
**Date:** 2026-05-03
**Status:** Confirmed (defect)
**Severity:** Medium

#### What Was It
`lib/onelogin/ruby-saml/slo_logoutrequest.rb:47` calls `REXML::Document.new(@request)` directly, bypassing the DOCTYPE / malformed-XML / NOENT protections that `safe_load_xml` adds. This is the inbound-parse entry for IdP-initiated logout requests.

#### How We Found It
Grep for every parser entrypoint not behind `safe_load_xml`. Compared against the symmetric paths in `Response` and `Logoutresponse` which both DO use `XMLSecurity::SignedDocument` → `safe_load_xml`.

#### Impact
DOCTYPE in inbound LogoutRequest reaches REXML directly; classic XXE for file-read or SSRF is structurally not possible in REXML 3.4.x (verified: REXML never dereferences external entities). However the attack surface for entity-expansion DoS, parser-quirk-driven mutations, and (if combined with F4) forged logout exists.

#### Evidence
- lib/onelogin/ruby-saml/slo_logoutrequest.rb:47

#### Next Steps / Open Questions
Reachability depends on whether the consuming SP allows POST-binding LogoutRequests at all. F4 below describes the bigger consequence.

---

### [RS-F4] ruby-saml: `validate_signature` fail-open for POST-binding LogoutRequest
**Date:** 2026-05-03
**Status:** Confirmed
**Severity:** Medium

#### What Was It
`SloLogoutrequest#validate_signature` (lib/onelogin/ruby-saml/slo_logoutrequest.rb:278-285) returns `true` immediately when `:get_params['Signature']` is absent. There is no embedded-XML-signature validation pathway for inbound logout requests. `is_valid?` returns true for forged unsigned LogoutRequests delivered via POST binding.

#### How We Found It
Read SloLogoutrequest's full validate chain. Compared with Response/Logoutresponse where validate_signature genuinely calls XMLSecurity::SignedDocument.

#### Impact
**Forced-logout primitive.** A consumer that calls `slo.is_valid?` and then logs out the user identified by `slo.name_id` (which is what omniauth-saml's `handle_logout_request` does) will accept a forged LogoutRequest. Attacker who can position a victim's browser to POST a LogoutRequest carrying the victim's NameID forces the victim out. Defense at the consumer is `name_id == session["saml_uid"]` (omniauth-saml saml.rb:235), which prevents arbitrary-user logout but not session-disruption / phishing-precursor flows.

#### Evidence
- lib/onelogin/ruby-saml/slo_logoutrequest.rb:278-285

#### Next Steps / Open Questions
GitLab-specific reachability is the open question — does GitLab call SloLogoutrequest, and if so, does it apply additional defense? Investigated in this session's Step 4a.

---

### [RS-F10] ruby-saml: `decrypt_element` regex NoMethodError as binary oracle
**Date:** 2026-05-03
**Status:** Confirmed (oracle source)
**Severity:** High (if SP leaks error states distinguishably)

#### What Was It
`response.rb:1110` does `elem_plaintext.match(regexp)[0]` where `regexp` is `/(.*<\/(\w+:)?Assertion>)/m` (or NameID/Attribute equivalents) without a nil-check on the match result. If the decrypted plaintext does not contain the expected close tag, `match` returns nil and `nil[0]` raises `NoMethodError`. This is a binary oracle: plaintext-contains-tag (proceeds, hits a different validation path) vs not (crashes immediately).

#### How We Found It
Reading the `decrypt_element` flow with Jager-Somorovsky XMLEnc oracle pattern in mind. Combined with F11 (CBC accepted) and F13 (padding=0).

#### Impact
Per-byte plaintext recovery / substitution for CBC-encrypted assertions, when the SP returns observably different responses for the two oracle states. Equivalent to Jager-Somorovsky 2011 confidentiality recovery on signed-then-encrypted SAML.

#### Evidence
- response.rb:1110, 1115
- utils.rb:368-373 (CBC accepted)
- utils.rb:384 (`cipher.padding = 0`)

#### Next Steps / Open Questions
The chain only works if the SP surfaces these states distinguishably. **Critical: per CLAUDE.md Rule 8, this is XMLEnc CONFIDENTIALITY recovery, not authentication bypass — the signature still catches any plaintext substitution.** See Chain C2 for the bounded impact analysis.

---

### [C2] Chain: CBC chosen-ciphertext + greedy regex + REXML re-parse → assertion content substitution
**Date:** 2026-05-03
**Status:** Candidate (theoretical chain — auth bypass impact requires verification per CLAUDE.md Rule 8)
**Severity:** Critical-if-exploitable; downgrades to confidentiality-only if signature catches substitution

#### What Was It
F10 (regex oracle) + F11 (CBC permitted) + F13 (padding disabled) + F5/F6 (REXML re-parse + greedy regex) compose to an XMLEnc oracle that may permit plaintext substitution of decrypted assertion content. The chain exploits CBC malleability to produce attacker-chosen plaintext that the post-decryption REXML parse then trusts.

#### How We Found It
Pattern recognition from Jager-Somorovsky 2011 + reading the post-decryption flow in ruby-saml. Combined the cryptographic primitive (F11/F13) with the parser primitive (F5/F6) and the oracle source (F10).

#### Impact (with the CLAUDE.md Rule 8 caveat)
- **Confidentiality:** plaintext recovery of an observed encrypted assertion. Real, not auth-bypass-class.
- **Authentication bypass:** ONLY if the chain produces substituted plaintext that the SP trusts AND the substitution does not break the signature on the same content. ruby-saml's flow re-validates the signature on `decrypted_document.referenced_xml` post-substitution. The signature was over the assertion's pre-encryption form. Substituting via CBC malleability changes the post-decryption form; the signature would no longer match.
- Net: this chain likely yields plaintext recovery (confidentiality) rather than auth bypass. Worth probing but should NOT be reported as auth-bypass without a working chain that proves the signature still verifies.

#### Evidence
- response.rb:1031-1063 (decrypted_document construction)
- response.rb:1095-1117 (decrypt_element)
- utils.rb:340-405 (decrypt_data)

#### Next Steps / Open Questions
Build a test bench that exercises the chain against ruby-saml. Determine empirically whether substitution survives signature validation. Per CLAUDE.md Rule 8, do not report as auth bypass without that proof.

---

### [GL-1] GitLab SAML sign-in flow does not enforce `InResponseTo` (login CSRF class)
**Date:** 2026-05-04
**Status:** Candidate; class publicly accepted-as-design industry-wide
**Severity:** Medium

#### What Was It
GitLab's `OmniauthCallbacksController#omniauth_flow` branches on `current_user`: if logged in, runs `IdentityLinker.link` which invokes `OriginValidator` (enforces in_response_to == session-stored request id); if NOT logged in, runs `sign_in_user_flow` which never invokes `OriginValidator`. omniauth-saml's `request_phase` (saml.rb:54-60) doesn't store the request UUID in session in the first place. Net: SAML sign-in flow does not validate that the response was correlated with a request GitLab itself issued.

#### How We Found It
Code review of `lib/gitlab/auth/saml/origin_validator.rb` and its only invocation site (identity_linker.rb), combined with reading `omniauth_callbacks_controller.rb` and tracing `current_user` branch.

#### Impact
Login CSRF: attacker positions a victim's browser to POST the attacker's own valid SAMLResponse to GitLab's `/users/auth/saml/callback`. Victim's session is established as the attacker. Subsequent victim actions (uploads, commits, key uploads) are recorded on the attacker's account. Industry-standard severity Medium (CVSS ~6).

#### Evidence
- lib/gitlab/auth/saml/origin_validator.rb (full file)
- lib/gitlab/auth/saml/identity_linker.rb:13 (`raise_unless_request_is_gitlab_initiated! if unlinked?`)
- app/controllers/omniauth_callbacks_controller.rb:160-194 (current_user branch)
- omniauth-saml saml.rb:54-60 (request_phase, no UUID storage)
- omniauth-saml saml.rb:168-182 (handle_response, no `:matches_request_id` plumbing)

#### Why It Was Not Yet Reported
Class is publicly known since 2016 (HackerOne #171398). The canonical maintainer response is: *"We accept this risk for the convenience of IdP-initiated SSO as defined in the standard. How do you propose we protect against the login CSRF without breaking IdP-initiated SSO?"* Searched H1 disclosed reports and GitLab's CVE registry — no GitLab-specific fix or report exists for this exact instance, but the class precedent strongly suggests the maintainer response will be the same.

#### Next Steps / Open Questions
Verify with a self-hosted lab (Docker GitLab CE + mock-saml IdP). Determine if EE patches add an enforcement layer I haven't seen. If reported, frame as "InResponseTo validation gap with proposed compatible fix" (enforce when InResponseTo is present, skip when blank for IdP-initiated).

---

### [DK-1] doorkeeper: token revocation bypass for public clients
**Date:** 2026-05-04
**Status:** Already fixed upstream (commit ecc1599, March 2026)
**Severity:** N/A (closed)

#### What Was It
`tokens_controller#authorized?` previously checked token ownership only when `token.application.confidential?`. Public-client tokens were revocable by any authenticating client. Fixed by removing the `confidential?` gate.

#### Why Documented
Variant-analysis seed for this session. The fix's commit message accepts "tokens with null application_id can be revoked without client authorization" as by-design — important context for DK-3.

---

### [GL-2] GitLab Instance SAML: `admin`/`auditor` flag set directly from SAML `groups` on every login
**Date:** 2026-05-04
**Status:** Confirmed (by-design); impact endpoint for any signature-bypass primitive
**Severity:** Critical-if-chained-with-signature-bypass; Medium-as-trust-amplifier in compromised-IdP scenarios

#### What Was It
`EE::Gitlab::Auth::Saml::User#find_user` (`ee/lib/ee/gitlab/auth/saml/user.rb:11-30`) sets `user.admin` and `user.auditor` directly from intersection of `auth_hash.groups` and `saml_config.admin_groups`/`auditor_groups`:
```ruby
user.admin = !(auth_hash.groups & saml_config.admin_groups).empty? if admin_groups_enabled?
user.auditor = !(auth_hash.groups & saml_config.auditor_groups).empty? if auditor_groups_enabled?
```
This runs on **every** login, not just first provisioning. A SAML response asserting the user is in an admin group (with valid signature) makes them an instance admin until the next login.

#### How We Found It
Source review of `ee/lib/ee/gitlab/auth/saml/user.rb` while mapping where SAML attributes drive privilege.

#### Impact
- **As-designed:** if an admin configures `admin_groups: ['gitlab-admins']` and IdP asserts user is in that group, instant admin. Standard SAML threat model — IdP is trusted.
- **As impact endpoint for a signature-bypass primitive:** ANY successful XPath/parser-differential variant (RS-F1, RS-F2 family) that lets an attacker change `auth_hash.groups` while keeping signature valid → instant **GitLab instance admin**. This is what would turn a Medium signature-handling bug into a Critical authentication-bypass-with-admin-impact.

This documents the high-water-mark impact ceiling for any SAML protocol-level finding against a GitLab-EE instance with `admin_groups` configured.

#### Evidence
- ee/lib/ee/gitlab/auth/saml/user.rb:25-26

#### Why Not Reportable Standalone
Without a primitive that breaks the SAML signature/structural binding, an attacker can't influence `auth_hash.groups`. The current code only reflects what the trusted IdP asserts. Reporting "GitLab uses SAML attributes to set admin" would be closed as by-design.

#### Next Steps / Open Questions
This is the chain target for any future signature-bypass finding. Specifically: combine with RS-F1 (parser differential), Chain C2 (CBC oracle if exploitable), or a future variant of CVE-2024-12093.

---

### [GL-3] GitLab Group SAML: `set_attributes_for_enterprise_user!` mass-assigns SAML attributes to managed users
**Date:** 2026-05-04
**Status:** Confirmed (bounded today by ALLOWED_USER_ATTRIBUTES allow-list)
**Severity:** Low today; High if ALLOWED_USER_ATTRIBUTES extended carelessly

#### What Was It
`Gitlab::Auth::GroupSaml::User#set_attributes_for_enterprise_user!` (`ee/lib/gitlab/auth/group_saml/user.rb:117-121`) mass-assigns `auth_hash.user_attributes.compact` to users who are `managed_by_group?`. The `auth_hash.user_attributes` for GroupSAML (defined in `ee/lib/gitlab/auth/group_saml/auth_hash.rb:18-24`) returns the intersection of SAML attributes with `ALLOWED_USER_ATTRIBUTES = %w[can_create_group projects_limit]`.

#### Evidence
- ee/lib/gitlab/auth/group_saml/user.rb:117-121
- ee/lib/gitlab/auth/group_saml/auth_hash.rb:9 (`ALLOWED_USER_ATTRIBUTES`)

#### Why Limited Today
The allow-list is short and the keys aren't admin-flag-class. `can_create_group` enables top-level group creation; `projects_limit` sets max projects. Both are limited to managed enterprise users (`user.managed_by_group?(saml_provider.group)`), not arbitrary users.

#### Why Worth Documenting
- The allow-list is a single change away from being dangerous. A future PR adding `external` or `confirmed_at` (or anything reaching `User` model attributes that affect privilege) without re-reviewing the mass-assignment site would create a vulnerability.
- Mass-assignment via `assign_attributes` doesn't go through ActiveRecord's strong-parameters-equivalent gates that normal user-edit paths use.

#### Next Steps / Open Questions
File a low-priority hardening report suggesting either: (a) explicit per-attribute assignment instead of `assign_attributes`, or (b) a `validates` lock on which attributes managed users can have changed via SAML. Probably won't pay; useful as a hardening contribution.

---

### [GL-4] Group SAML sign-in flow has same OriginValidator gap as instance SAML
**Date:** 2026-05-04
**Status:** Confirmed
**Severity:** Medium

#### What Was It
`Groups::OmniauthCallbacksController#group_saml` (`ee/app/controllers/groups/omniauth_callbacks_controller.rb:14-24`) delegates to `omniauth_flow(Gitlab::Auth::GroupSaml, identity_linker: identity_linker)`. The `omniauth_flow` parent (in base `OmniauthCallbacksController`) branches on `current_user`: `link_identity` (which runs IdentityLinker → OriginValidator) when present, `sign_in_user_flow` (no OriginValidator) otherwise. Same gap as GL-1 but for a separate callback endpoint (`/users/auth/group_saml/callback`).

#### Evidence
- ee/app/controllers/groups/omniauth_callbacks_controller.rb:14-24
- Same `omniauth_flow` `current_user` branch as GL-1

#### Mitigation Already In Place
The Group SAML's `safe_relay_state` (line 148-150) is gated on `valid_gitlab_initiated_saml_request?`, closing CVE-2023-1965. So login-CSRF + RelayState chain to OAuth token theft is blocked. The base login-CSRF (just having victim's browser sign in as attacker) remains.

#### Next Steps / Open Questions
Same as GL-1. Lab verification needed.

---

### [DK-3] doorkeeper: `validate_client_match` allows ownerless refresh tokens
**Date:** 2026-05-04
**Status:** Ruled Out — consistent with by-design ownerless-token model
**Severity:** Informational

#### What Was It
`refresh_token_request.rb:116-120` `validate_client_match` returns true unconditionally when `refresh_token.application_id.blank?`. Same shape as the just-fixed revocation bug.

#### Why It Was Ruled Out
Ownerless tokens are produced only via `password_access_token_request` with `skip_client_authentication_for_password_grant: true` AND no client credentials in the request. In that flow, the resulting refresh_token has no client binding by design — there's no owner to authenticate against. The maintainer's commit message on the revocation fix explicitly accepts this model. Same logic applies to refresh.

#### Next Steps / Open Questions
None. Closed.

