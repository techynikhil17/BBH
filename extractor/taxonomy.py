"""Canonical vulnerability taxonomy and feature taxonomy with normalization aliases.

The taxonomy is the source of truth for `vuln_class` and `affected_feature_type`
fields on ExtractedPattern. Anything that doesn't normalize cleanly is a candidate
for the novel-pattern flag.
"""

from __future__ import annotations

VULN_CLASSES: tuple[str, ...] = (
    "ssrf",
    "rce",
    "idor",
    "sqli",
    "xxe",
    "ssti",
    "auth_bypass",
    "deserialization",
    "race_condition",
    "business_logic",
    "mass_assignment",
    "subdomain_takeover",
    "file_upload",
    "graphql",
    "oauth_misconfig",
    "open_redirect",
    "xss",
    "csrf",
    "info_disclosure",
    "path_traversal",
    "command_injection",
    "prototype_pollution",
    "ldap_injection",
    "nosql_injection",
    "cache_poisoning",
    "host_header_injection",
    "request_smuggling",
    "cors_misconfig",
    "jwt_flaw",
    "rate_limit_bypass",
)

VULN_ALIASES: dict[str, str] = {
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "ssrf (server-side request forgery)": "ssrf",
    "remote code execution": "rce",
    "code execution": "rce",
    "arbitrary code execution": "rce",
    "insecure direct object reference": "idor",
    "insecure direct object references": "idor",
    "broken object level authorization": "idor",
    "bola": "idor",
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "second order sql injection": "sqli",
    "xml external entity": "xxe",
    "xml external entities": "xxe",
    "server-side template injection": "ssti",
    "server side template injection": "ssti",
    "template injection": "ssti",
    "authentication bypass": "auth_bypass",
    "auth bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "insecure deserialization": "deserialization",
    "unsafe deserialization": "deserialization",
    "object deserialization": "deserialization",
    "toctou": "race_condition",
    "time of check time of use": "race_condition",
    "logic flaw": "business_logic",
    "logic bug": "business_logic",
    "business logic": "business_logic",
    "broken business logic": "business_logic",
    "mass-assignment": "mass_assignment",
    "parameter binding vulnerability": "mass_assignment",
    "subdomain takeover": "subdomain_takeover",
    "dangling dns": "subdomain_takeover",
    "dangling cname": "subdomain_takeover",
    "unrestricted file upload": "file_upload",
    "arbitrary file upload": "file_upload",
    "graphql introspection": "graphql",
    "graphql batching": "graphql",
    "graphql query depth": "graphql",
    "oauth misconfiguration": "oauth_misconfig",
    "oauth flaw": "oauth_misconfig",
    "oauth": "oauth_misconfig",
    "open redirect": "open_redirect",
    "unvalidated redirect": "open_redirect",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "dom-based xss": "xss",
    "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf",
    "information disclosure": "info_disclosure",
    "info leak": "info_disclosure",
    "data exposure": "info_disclosure",
    "sensitive information exposure": "info_disclosure",
    "directory traversal": "path_traversal",
    "path traversal": "path_traversal",
    "lfi": "path_traversal",
    "local file inclusion": "path_traversal",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "shell injection": "command_injection",
    "prototype pollution": "prototype_pollution",
    "ldap injection": "ldap_injection",
    "nosql injection": "nosql_injection",
    "mongodb injection": "nosql_injection",
    "cache poisoning": "cache_poisoning",
    "web cache poisoning": "cache_poisoning",
    "host header injection": "host_header_injection",
    "host header attack": "host_header_injection",
    "request smuggling": "request_smuggling",
    "http request smuggling": "request_smuggling",
    "http desync": "request_smuggling",
    "cors misconfiguration": "cors_misconfig",
    "cors": "cors_misconfig",
    "jwt": "jwt_flaw",
    "jwt vulnerability": "jwt_flaw",
    "jwt none algorithm": "jwt_flaw",
    "rate limit bypass": "rate_limit_bypass",
    "missing rate limit": "rate_limit_bypass",
}

FEATURE_TYPES: tuple[str, ...] = (
    "webhook",
    "pdf_export",
    "file_upload",
    "image_fetch",
    "url_import",
    "api_endpoint",
    "graphql_endpoint",
    "oauth_flow",
    "admin_panel",
    "user_profile",
    "payment_flow",
    "batch_operation",
    "export_function",
    "import_function",
    "search_endpoint",
    "auth_endpoint",
    "password_reset",
    "registration",
    "session_management",
    "file_download",
    "preview_generator",
    "thumbnail_service",
    "report_generator",
    "notification_service",
    "integration_callback",
    "redirect_handler",
    "session_token_endpoint",
    "comment_system",
    "messaging",
    "billing",
    "subscription_management",
    "team_management",
    "permission_management",
    "api_key_management",
    "sso_flow",
)

FEATURE_ALIASES: dict[str, str] = {
    "webhook handler": "webhook",
    "webhook callback": "webhook",
    "callback handler": "webhook",
    "pdf generator": "pdf_export",
    "pdf export": "pdf_export",
    "pdf rendering": "pdf_export",
    "html to pdf": "pdf_export",
    "image upload": "file_upload",
    "avatar upload": "file_upload",
    "attachment upload": "file_upload",
    "image proxy": "image_fetch",
    "image fetcher": "image_fetch",
    "remote image fetch": "image_fetch",
    "url import": "url_import",
    "url fetcher": "url_import",
    "import from url": "url_import",
    "rest endpoint": "api_endpoint",
    "rest api": "api_endpoint",
    "graphql": "graphql_endpoint",
    "graphql api": "graphql_endpoint",
    "oauth": "oauth_flow",
    "oauth flow": "oauth_flow",
    "oauth callback": "oauth_flow",
    "admin": "admin_panel",
    "admin dashboard": "admin_panel",
    "user settings": "user_profile",
    "profile page": "user_profile",
    "checkout": "payment_flow",
    "checkout flow": "payment_flow",
    "stripe integration": "payment_flow",
    "billing flow": "payment_flow",
    "bulk action": "batch_operation",
    "batch action": "batch_operation",
    "csv export": "export_function",
    "data export": "export_function",
    "csv import": "import_function",
    "data import": "import_function",
    "search": "search_endpoint",
    "search api": "search_endpoint",
    "login": "auth_endpoint",
    "login endpoint": "auth_endpoint",
    "signin": "auth_endpoint",
    "forgot password": "password_reset",
    "password recovery": "password_reset",
    "signup": "registration",
    "signup form": "registration",
    "register": "registration",
    "session": "session_management",
    "session token": "session_management",
    "download": "file_download",
    "preview": "preview_generator",
    "link preview": "preview_generator",
    "thumbnail": "thumbnail_service",
    "report": "report_generator",
    "report generation": "report_generator",
    "notification": "notification_service",
    "email notification": "notification_service",
    "redirect": "redirect_handler",
    "redirect endpoint": "redirect_handler",
    "comments": "comment_system",
    "chat": "messaging",
    "direct message": "messaging",
    "subscription": "subscription_management",
    "team settings": "team_management",
    "permissions": "permission_management",
    "role management": "permission_management",
    "api key": "api_key_management",
    "personal access token": "api_key_management",
    "sso": "sso_flow",
    "saml": "sso_flow",
}


def normalize_vuln_class(raw: str | None) -> str:
    """Normalize a free-text vuln class to a canonical taxonomy entry.

    Returns the canonical entry if found in `VULN_CLASSES` directly or via
    `VULN_ALIASES`. Otherwise returns the lower-cased input — caller should
    flag this as novel.
    """
    if not raw:
        return ""
    key = raw.strip().lower()
    if key in VULN_CLASSES:
        return key
    if key in VULN_ALIASES:
        return VULN_ALIASES[key]
    # Try with underscores swapped for spaces and vice versa
    spaced = key.replace("_", " ")
    if spaced in VULN_ALIASES:
        return VULN_ALIASES[spaced]
    underscored = key.replace(" ", "_")
    if underscored in VULN_CLASSES:
        return underscored
    return key


def normalize_feature_type(raw: str | None) -> str:
    """Normalize a feature type to a canonical taxonomy entry."""
    if not raw:
        return ""
    key = raw.strip().lower()
    if key in FEATURE_TYPES:
        return key
    if key in FEATURE_ALIASES:
        return FEATURE_ALIASES[key]
    spaced = key.replace("_", " ")
    if spaced in FEATURE_ALIASES:
        return FEATURE_ALIASES[spaced]
    underscored = key.replace(" ", "_")
    if underscored in FEATURE_TYPES:
        return underscored
    return key


def is_known_vuln_class(value: str) -> bool:
    return value in VULN_CLASSES


def is_known_feature_type(value: str) -> bool:
    return value in FEATURE_TYPES


def taxonomy_summary() -> str:
    """Render a stable, sorted summary of the taxonomy for inclusion in prompts.

    The output is deterministic — sorted lists and stable separators — so it
    can sit safely inside a cached prompt prefix without invalidating the cache.
    """
    vuln_lines = "\n".join(f"- {v}" for v in sorted(VULN_CLASSES))
    feature_lines = "\n".join(f"- {f}" for f in sorted(FEATURE_TYPES))
    return (
        "VULNERABILITY CLASSES (canonical):\n"
        f"{vuln_lines}\n\n"
        "FEATURE TYPES (canonical):\n"
        f"{feature_lines}\n"
    )
