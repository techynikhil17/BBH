from pathlib import Path

from generator.pipeline.index_builder import (
    build_index,
    discover_skills,
    write_index,
)


_SKILL_TEMPLATE = """# SKILL: {name}
**Category:** {cat}
**Severity Range:** {sev}
**Typical Payout:** {payout}
**Pattern Count:** {n}
**Last Updated:** {date}
**Version:** 1.0.0

---

## OVERVIEW
x

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
{chain_rows}

## REPORTING TEMPLATE HINTS
y
"""


def _write_skill(skills_dir: Path, vuln_class, slug, **kw):
    d = skills_dir / vuln_class / slug
    d.mkdir(parents=True)
    (d / "skill.md").write_text(_SKILL_TEMPLATE.format(**kw), encoding="utf-8")


def test_discover_skips_templates_dir(tmp_path):
    (tmp_path / "_templates").mkdir()
    (tmp_path / "_templates" / "skill.md").write_text("# SKILL: tmpl", encoding="utf-8")
    _write_skill(
        tmp_path,
        "ssrf",
        "cloud-metadata",
        name="SSRF — Cloud",
        cat="ssrf > cloud-metadata",
        sev="high",
        payout="$1000",
        n=3,
        date="2026-05-01",
        chain_rows="| info_disclosure | x | y | high |",
    )
    found = discover_skills(tmp_path)
    assert len(found) == 1
    assert found[0].metadata.skill_name == "SSRF — Cloud"


def test_index_table_sorted_by_severity_then_count(tmp_path):
    _write_skill(
        tmp_path, "ssrf", "blind",
        name="SSRF Blind", cat="ssrf > blind", sev="medium", payout="$500", n=2, date="2026-05-01",
        chain_rows="| info_disclosure | x | y | medium |",
    )
    _write_skill(
        tmp_path, "rce", "ssti",
        name="RCE SSTI", cat="rce > ssti", sev="critical", payout="$5000", n=4, date="2026-05-01",
        chain_rows="| info_disclosure | x | y | high |",
    )
    _write_skill(
        tmp_path, "rce", "java",
        name="RCE Java Deser", cat="rce > deser", sev="critical", payout="$8000", n=2, date="2026-05-01",
        chain_rows="| info_disclosure | x | y | high |",
    )

    found = discover_skills(tmp_path)
    rendered = build_index(found)

    # Critical comes first, with the higher pattern count first within tier
    pos_ssti = rendered.index("RCE SSTI")
    pos_java = rendered.index("RCE Java Deser")
    pos_blind = rendered.index("SSRF Blind")
    assert pos_ssti < pos_java < pos_blind


def test_index_chain_summary_counts(tmp_path):
    _write_skill(
        tmp_path, "ssrf", "blind",
        name="A", cat="x", sev="medium", payout="$0", n=1, date="d",
        chain_rows="| info_disclosure | x | y | medium |\n| rce | a | b | low |",
    )
    _write_skill(
        tmp_path, "rce", "ssti",
        name="B", cat="x", sev="critical", payout="$0", n=1, date="d",
        chain_rows="| info_disclosure | x | y | high |",
    )
    found = discover_skills(tmp_path)
    rendered = build_index(found)
    assert "Chain Summary" in rendered
    # info_disclosure cited by 2 skills, rce by 1
    assert "info_disclosure" in rendered.lower()


def test_write_index_creates_readme(tmp_path):
    _write_skill(
        tmp_path, "idor", "seq",
        name="IDOR Seq", cat="idor > seq", sev="medium", payout="$300", n=2, date="2026-05-01",
        chain_rows="| info_disclosure | x | y | medium |",
    )
    out = write_index(skills_dir=tmp_path)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Bug Bounty Skills Library" in content
    assert "IDOR Seq" in content


def test_index_handles_empty_dir(tmp_path):
    rendered = build_index([])
    assert "no skills generated yet" in rendered
