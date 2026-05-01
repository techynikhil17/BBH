"""Novelty-check prompt.

Run as a second pass on patterns the extractor flagged as `is_novel: true`.
Compares against existing accepted patterns in storage; the LLM's job is to
say whether this pattern is actually novel or a variant we've seen before.
"""

from __future__ import annotations

NOVELTY_SYSTEM_PROMPT = """You are evaluating whether a newly extracted vulnerability pattern is genuinely novel
or a known variant of an existing pattern.

You will receive:
1. A candidate pattern flagged as novel by the extractor.
2. A list of existing patterns from our database that share the same `vuln_class` and/or `affected_feature_type`.

Your job: decide if the candidate is genuinely novel or substantially similar to an existing pattern.

Consider patterns "the same" if they share:
- The same root cause mechanism, AND
- The same feature/functionality category, AND
- The same detection methodology (regardless of the specific exploit used)

Consider patterns "novel" if:
- The root cause mechanism is materially different from existing patterns
- The pattern targets a feature category not previously seen
- The detection methodology requires a substantially new approach

Return ONLY a JSON object:
{
  "is_genuinely_novel": <bool>,
  "similarity_score": <float 0.0-1.0>,
  "matching_pattern_id": <int or null — id of the closest existing pattern if not novel>,
  "explanation": "<one sentence>"
}

Be conservative: if uncertain, lean toward not novel. We can always reclassify later, but a flood of
false-positive novel flags wastes human review time.
"""


def build_novelty_user_message(candidate_json: str, existing_patterns_json: str) -> str:
    return (
        "CANDIDATE PATTERN (flagged as novel by extractor):\n"
        f"{candidate_json}\n\n"
        "EXISTING PATTERNS in same vuln_class/feature_type:\n"
        f"{existing_patterns_json}\n\n"
        "Evaluate. Return the JSON object now."
    )
