"""Walk skills/ and emit skills/README.md as the index.

Header layout:
    | Skill | Category | Severity | Patterns | Payout Range | Version | Updated |

Sorted by:
    1. severity (critical → low → unknown)
    2. pattern count descending

A "Chain Summary" appears at the bottom enumerating the most-mentioned chain
targets across all skills (parsed from each skill's CHAIN OPPORTUNITIES table).
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import SKILLS_DIR
from ..models import SkillMetadata

logger = logging.getLogger(__name__)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "": 5}

_HEADER_PATTERN = re.compile(r"^\*\*(?P<key>[^:]+):\*\*\s*(?P<value>.+?)\s*$", re.MULTILINE)
_SKILL_NAME_PATTERN = re.compile(r"^#\s+SKILL:\s*(?P<name>.+?)\s*$", re.MULTILINE)
_CHAIN_TABLE_PATTERN = re.compile(
    r"^##\s+CHAIN OPPORTUNITIES\s*$"
    r"(?P<table>(?:\n|.)*?)"
    r"(?=^##\s)",
    re.MULTILINE,
)
_CHAIN_ROW_PATTERN = re.compile(
    r"^\|\s*(?P<target>[^|]+?)\s*\|\s*(?P<impact>[^|]*?)\s*\|\s*[^|]*?\s*\|\s*(?P<conf>[^|]*?)\s*\|$",
    re.MULTILINE,
)


@dataclass
class _ParsedSkill:
    metadata: SkillMetadata
    chain_targets: list[str]


def _severity_sort_key(meta: SkillMetadata) -> tuple[int, int]:
    """Lower is better — primary key for the sort.

    For severity ranges like "high-critical" we use the strongest end as the
    sort key, so high-impact skills float to the top.
    """
    severity = (meta.severity_range or "").strip().lower()
    if not severity:
        sev_key = SEVERITY_ORDER[""]
    else:
        # Range like "high-critical" → take the strongest token
        tokens = re.split(r"[-/–—]", severity)
        sev_key = min(SEVERITY_ORDER.get(t.strip(), 99) for t in tokens)
    return (sev_key, -meta.pattern_count)


def _parse_skill_md(path: Path, root: Path) -> Optional[_ParsedSkill]:
    """Parse one skill.md file into header metadata + chain targets."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("could not read %s: %s", path, exc)
        return None

    name_match = _SKILL_NAME_PATTERN.search(text)
    if not name_match:
        return None
    skill_name = name_match.group("name").strip()

    headers: dict[str, str] = {
        m.group("key").strip(): m.group("value").strip()
        for m in _HEADER_PATTERN.finditer(text[: text.find("---") if "---" in text else len(text)])
    }

    try:
        rel_path = path.relative_to(root.parent)
    except ValueError:
        rel_path = path

    metadata = SkillMetadata(
        skill_name=skill_name,
        category=headers.get("Category", ""),
        severity_range=headers.get("Severity Range", ""),
        typical_payout=headers.get("Typical Payout", ""),
        pattern_count=int(headers.get("Pattern Count", "0").split()[0] or 0)
        if headers.get("Pattern Count", "0").split()
        else 0,
        last_updated=headers.get("Last Updated", ""),
        version=headers.get("Version", "1.0.0"),
        path=str(rel_path),
    )

    chain_targets: list[str] = []
    chain_match = _CHAIN_TABLE_PATTERN.search(text + "\n## __END__\n")
    if chain_match:
        for row in _CHAIN_ROW_PATTERN.finditer(chain_match.group("table")):
            target = row.group("target").strip()
            if target and target.lower() not in ("chain to", "---", "------"):
                chain_targets.append(target)

    return _ParsedSkill(metadata=metadata, chain_targets=chain_targets)


def discover_skills(skills_dir: Path = SKILLS_DIR) -> list[_ParsedSkill]:
    """Find every ``skill.md`` under ``skills_dir`` (skipping ``_templates/``)."""
    if not skills_dir.exists():
        return []
    skills: list[_ParsedSkill] = []
    for path in sorted(skills_dir.rglob("skill.md")):
        # Skip the blank template under _templates/
        if "_templates" in path.parts:
            continue
        parsed = _parse_skill_md(path, skills_dir)
        if parsed:
            skills.append(parsed)
    return skills


def build_index(skills: list[_ParsedSkill]) -> str:
    """Render the README.md content as a single markdown string."""
    lines: list[str] = [
        "# Bug Bounty Skills Library",
        "",
        f"Auto-generated index of {len(skills)} skill(s). Run "
        "`python -m generator.main index` to regenerate.",
        "",
        "## Skills",
        "",
        "| Skill | Category | Severity | Patterns | Payout Range | Version | Updated |",
        "|-------|----------|----------|---------:|--------------|---------|---------|",
    ]

    skills_sorted = sorted(skills, key=lambda s: _severity_sort_key(s.metadata))
    for parsed in skills_sorted:
        m = parsed.metadata
        link = f"[{m.skill_name}]({m.path})" if m.path else m.skill_name
        lines.append(
            f"| {link} | {m.category or '-'} | {m.severity_range or '-'} | "
            f"{m.pattern_count} | {m.typical_payout or '-'} | "
            f"{m.version or '-'} | {m.last_updated or '-'} |"
        )

    if not skills:
        lines.append("| _no skills generated yet_ | | | | | | |")

    # Chain summary
    chain_counter: Counter[str] = Counter()
    for parsed in skills:
        for target in parsed.chain_targets:
            chain_counter[target.lower()] += 1

    lines.extend(["", "## Chain Summary", ""])
    if chain_counter:
        lines.append("Targets most frequently referenced in CHAIN OPPORTUNITIES tables:")
        lines.append("")
        lines.append("| Chain Target | Skills Referencing |")
        lines.append("|--------------|--------------------:|")
        for target, count in chain_counter.most_common(15):
            lines.append(f"| {target} | {count} |")
    else:
        lines.append("No chain targets recorded yet.")

    return "\n".join(lines) + "\n"


def write_index(
    skills_dir: Path = SKILLS_DIR,
    output_path: Optional[Path] = None,
) -> Path:
    """Discover skills under ``skills_dir`` and write the README index."""
    skills = discover_skills(skills_dir)
    content = build_index(skills)
    output_path = output_path or (skills_dir / "README.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path
