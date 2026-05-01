"""Classification / normalization prompt.

Used as a lightweight follow-up when the extractor returns a `vuln_class` or
`affected_feature_type` that doesn't match the taxonomy directly. Keeps the
LLM call narrow — single-purpose, small input.
"""

from __future__ import annotations

from ..taxonomy import taxonomy_summary

CLASSIFICATION_SYSTEM_PROMPT = """You are a vulnerability taxonomy normalizer.

Given a free-text vulnerability description and a list of canonical vulnerability
classes, return the SINGLE best canonical match — or "novel" if none fit cleanly.

Return ONLY a JSON object of the form:
{"vuln_class": "<canonical_value_or_novel>", "feature_type": "<canonical_value_or_novel>"}

If the input describes a pattern that is genuinely outside the taxonomy, use "novel"
for the corresponding field. Do not invent new canonical labels.

""" + taxonomy_summary()


def build_classification_user_message(
    raw_vuln_class: str,
    raw_feature_type: str,
    context_snippet: str = "",
) -> str:
    parts = [
        "Classify the following report content into the canonical taxonomy.",
        f"Suggested vuln_class: {raw_vuln_class!r}",
        f"Suggested feature_type: {raw_feature_type!r}",
    ]
    if context_snippet:
        snippet = context_snippet.strip()
        if len(snippet) > 800:
            snippet = snippet[:800] + "..."
        parts.append(f"\nContext: {snippet}")
    parts.append("\nReturn the canonical-form JSON now.")
    return "\n".join(parts)
