# SAML Security Research Context
# Target: GitLab SAML Authentication
# Objective: Find authentication bypass vulnerabilities

## Architecture Under Test

GitLab uses a layered SAML stack:
- GitLab Rails custom SAML code (lib/gitlab/auth/saml/)
- omniauth-saml gem (OmniAuth strategy layer)  
- ruby-saml gem (core SAML processing)
- Nokogiri (libxml2 C wrapper for XML/canonicalization)
- REXML (pure Ruby XML parser, used alongside Nokogiri)

This dual-parser architecture is the primary attack surface.

## Attack Category 1: Parser Differential Attacks

The core vulnerability class. ruby-saml uses TWO different XML parsers
during signature validation:
- REXML extracts: DigestValue, SignatureValue, signed element ID
- Nokogiri extracts: the actual signed element, performs canonicalization

If these two parsers can be made to "see" different elements for the
same query, signature validation passes on element-A while the
application processes element-B.

### Known Exploited Differentials (ALL PATCHED)

1. REXML NotationDecl quote mutation (Mattermost/Juho Forsén 2021)
   - SYSTEM identifier quote mismatch on round-trip causes document mutation
   - Downstream: OneLogin ruby-saml bypass

2. REXML ATTLIST doctype namespace confusion (CVE-2025-25291/25292)
   - ATTLIST declarations allow duplicate namespace attributes
   - REXML and Nokogiri resolve namespace-prefixed attributes differently
   - Used to bypass GitLab authentication

3. libxml2 xmlCopyDoc entity hash skip (CVE-2025-23369)
   - xmlCopyDoc does not copy XML_TEXT_NODE children of entity refs
   - XPath hash comparison skips XML_ENTITY_REF_NODE, returns 0
   - Result: XPath finds wrong element in dup'd document
   - GitHub Enterprise bypass

4. Void Canonicalization via relative namespace URI (CVE-2025-66568)
   - xmlns:ns="1" (relative URI) causes libxml2 canonicalization error
   - Nokogiri silently returns empty string instead of failing
   - DigestValue of empty string (47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=) passes
   - Does NOT require valid credentials - WS-Fed metadata is sufficient signature source

5. Extensions DigestValue smuggling (CVE-2024-45409)
   - XPath query //ds:DigestValue finds FIRST occurrence in document
   - samlp:Extensions allows arbitrary child elements
   - Injected DigestValue in Extensions takes priority over real one
   - Requires a valid signed assertion (any user on the instance)

6. Encrypted assertion signature ordering bypass (CVE-2024-9487)
   - Signatures extracted pre-decryption
   - After decryption, new assertion appears but its signature is unvalidated
   - GitHub Enterprise specific but pattern applies anywhere with encrypted assertions

### Key Technical Details for Exploitation

libxml2 XPath comparison function xmlXPathEqualNodeSetString:
- Uses xmlXPathNodeValHash as optimization before string comparison
- Hash function skips XML_ENTITY_REF_NODE (returns 0)
- After document.dup, entity ref children not preserved
- Result: "Aid198..." entity ref hashes same as "_id198" plain text

Nokogiri attribute lookup (node['ID'] or node.attribute('ID')):
- Ignores namespaces, uses simple name only
- When duplicate simple names exist (ID vs samlp:ID), behavior undefined
- REXML and Nokogiri choose DIFFERENT attribute when duplicates exist

xml reserved prefix abuse:
- xml:xmlns is not a valid attribute per spec
- REXML treats it as regular attribute, alters namespace resolution
- Can hide/show Signature elements to specific parsers

## Attack Category 2: XML Signature Wrapping (XSW)

Classic attack. Move signed element to non-processed location,
insert unsigned evil element where processor expects signed element.

8 standard variants (XSW1-8) all documented and tested by SAML Raider.
ruby-saml 1.18.0 defends against known variants by:
- Checking doc.errors.any? for Nokogiri parse errors
- Verifying signature parent is Assertion or Response
- Checking ID uniqueness via schema validation

### Unexplored XSW Surface
- XSW via ECP binding (different code path, may be unpatched)
- XSW with encrypted assertions (pre/post decryption document mismatch)
- XSW targeting GitLab's custom wrapper layer above ruby-saml

## Attack Category 3: Spec-Level Logic Bugs

Vulnerabilities from incorrect implementation of SAML spec requirements.

### Unsolicited Response Attack
SAML spec section 4.1.5: IdP-initiated SSO responses have NO InResponseTo.
Many SPs accept unsolicited responses without checking if they're configured to.
Combined with TRC: use a valid response from SP-A at SP-B with InResponseTo stripped.

### AudienceRestriction OR vs AND
Spec requires ALL AudienceRestriction elements to be satisfied (AND logic).
Some implementations do OR (any match sufficient).
Attack: add second AudienceRestriction with target SP's entity ID to assertion
signed for attacker-controlled SP.

### Multiple ACS Endpoints
Spec allows multiple AssertionConsumerService endpoints with different indices.
Each index may have different validation code path.
Test: submit responses to secondary ACS endpoints (/saml/callback?index=1 etc)

### Attribute Extraction vs Signature Scope
GitLab reads authorization data (groups, admin) from AttributeStatement.
If attribute extraction happens after validation but with different parser,
unsigned attributes may influence authorization.

## Attack Category 4: GitLab-Specific Custom Code Issues

### auth_hash Layer
OmniAuth produces auth_hash object from ruby-saml Response.
GitLab reads uid/email from auth_hash, not directly from ruby-saml.
Potential: ruby-saml validates one value, auth_hash exposes another.

### NameID Normalization
GitLab may normalize NameID (downcase, strip whitespace).
If signed value is "Admin@co.com" but normalized to "admin@co.com",
and admin@co.com exists, authentication succeeds with wrong identity.

### Group/Admin Attribute Injection
GitLab SAML config maps SAML attributes to admin/group status.
These attributes live in AttributeStatement - check if they're
within the signed scope or can be injected separately.

## Known Signature Sources (No Credentials Required)

For attacks requiring a valid signature (parser differential attacks),
these sources provide signed XML without needing a GitLab account:

1. WS-Federation metadata:
   https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
   (Same certificate as SAML signing - publicly accessible)

2. GitLab SAML metadata response signing:
   GET /users/auth/saml/metadata
   (Check if signed in response headers or body)

3. IdP error responses:
   Send malformed AuthnRequest, IdP may return signed error response

4. Expired SAML responses from public sources:
   Bug reports, documentation, conference talks often contain real responses

## Key Files to Analyze

### ruby-saml (primary target)
- lib/onelogin/ruby-saml/response.rb
- lib/onelogin/ruby-saml/xml_security.rb
- lib/onelogin/ruby-saml/utils.rb

### GitLab custom SAML (secondary target)
- lib/gitlab/auth/saml/auth_hash.rb
- lib/gitlab/auth/saml/config.rb
- lib/gitlab/auth/saml/user.rb
- lib/gitlab/auth/saml/identity_linker.rb
- lib/gitlab/auth/omniauth_callbacks/saml.rb
- app/controllers/omniauth_callbacks_controller.rb

### Configuration
- config/initializers/omniauth.rb (or similar)
- Check Gemfile.lock for exact ruby-saml version

## Research Questions (Priority Order)

### P0 - Most Likely to Yield New Bugs
1. Does ruby-saml 1.18.0 actually catch relative namespace URIs in doc.errors?
   Test: parse xmlns:ns="1" with Nokogiri, check doc.errors.any?
   If false: Void Canonicalization still works on latest version

2. Are there any remaining // XPath queries in xml_security.rb after 1.18.0 patches?
   Any // query that reads security-critical data is potentially exploitable.

3. Does GitLab's ECP binding support (if any) share validation code with browser SSO?
   If separate: ECP path may be completely unpatched.

4. Does GitLab's custom auth_hash layer introduce any normalization that creates
   a differential between what ruby-saml validated and what GitLab acts on?

### P1 - Novel Attack Vectors
5. Encrypted NameID decryption: is decrypted content re-parsed? With which parser?
   If re-parsed with Nokogiri after signature validation: new differential window.

6. Multiple ACS endpoints: does GitLab expose any secondary endpoints with
   different validation logic?

7. Extensions element recursive injection: does schema validation catch
   nested samlp:Extensions containing ds:DigestValue?

### P2 - Logic Bugs
8. Unsolicited response handling: does GitLab reject unsolicited responses
   when not configured for IdP-initiated SSO?

9. AudienceRestriction: does GitLab evaluate multiple AudienceRestriction
   elements with AND or OR logic?

10. Attribute normalization: what normalization does GitLab apply to NameID
    before looking up users?

## Testing Setup

### Local GitLab SAML Testing
```bash
# docker-compose for local GitLab with SAML
# Use SimpleSAMLphp or similar as test IdP
# Configure gitlab.rb with SAML settings
```

### Minimal Bypass Test (Void Canonicalization)
```ruby
require 'nokogiri'

# Test if relative namespace URI triggers Nokogiri error
xml = '<?xml version="1.0"?><samlp:Response xmlns:ns="1"><samlp:Assertion/></samlp:Response>'
doc = Nokogiri::XML(xml) { |c| c.options = Nokogiri::XML::ParseOptions::STRICT }
puts "Errors: #{doc.errors.any?}"  # Should be true if 1.18.0 catches it

# Test canonicalization behavior
canon = doc.root.canonicalize
puts "Canon length: #{canon.length}"  # If 0: void canon still works
```

### Key Tool: SAML Raider (Burp Extension)
- Intercept SAMLResponse
- Apply XSW variants 1-8 automatically
- Remove signatures
- Re-sign with custom certificate

## Responsible Disclosure

GitLab security: https://about.gitlab.com/security/disclosure/
HackerOne program: https://hackerone.com/gitlab
Severity guide: Auth bypass = Critical (up to $33,500 bounty)