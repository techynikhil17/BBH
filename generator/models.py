"""Internal models for the skill generator.

These are the shapes that flow through the pipeline:
- ``PatternGroup``: a (vuln_class, vuln_subtype) bucket + its patterns
- ``GenerationTask``: the JSON payload written to PENDING_DIR
- ``GenerationCompletion``: the JSON payload Claude Code writes to COMPLETED_DIR
- ``SkillMetadata``: parsed-out header info used by the index builder
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class PatternGroup(BaseModel):
    """A bucket of patterns sharing (vuln_class, vuln_subtype).

    Buckets with fewer than ``MIN_PATTERNS_PER_GROUP`` patterns are excluded
    upstream in the grouper.
    """

    vuln_class: str
    vuln_subtype: str
    patterns: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def task_id(self) -> str:
        # task_id matches the file name we'll write under PENDING_DIR
        from .config import TASK_ID_PREFIX

        safe_subtype = (self.vuln_subtype or "general").replace("/", "_").replace(" ", "-")
        return f"{TASK_ID_PREFIX}_{self.vuln_class}_{safe_subtype}"

    @property
    def slug(self) -> str:
        """Filesystem-safe identifier used inside ``skills/...``."""
        return (self.vuln_subtype or "general").replace("/", "_").replace(" ", "-").lower()


class GenerationTask(BaseModel):
    """Shape of the JSON payload written to ``data/claude_tasks/pending/<task_id>.json``."""

    task_id: str
    task_type: str = "skill_generation"
    vuln_class: str
    vuln_subtype: str
    patterns: list[dict[str, Any]]
    existing_skill: Optional[str] = None
    existing_patterns: Optional[list[dict[str, Any]]] = None
    new_pattern_urls: Optional[list[str]] = None
    instruction: str
    schema_template: str
    expected_output_path: str
    is_update: bool = False


class GenerationCompletion(BaseModel):
    """Shape Claude Code writes to ``data/claude_tasks/completed/<task_id>.json``."""

    skill_md_content: str
    patterns_json: list[dict[str, Any]]
    metadata: dict[str, Any] = Field(default_factory=dict)


class SkillMetadata(BaseModel):
    """Header metadata parsed from a skill.md by the index builder."""

    skill_name: str
    category: str  # "<vuln_class> > <vuln_subtype>"
    severity_range: str = ""
    typical_payout: str = ""
    pattern_count: int = 0
    last_updated: str = ""
    version: str = "1.0.0"
    path: str = ""  # repo-relative path to skill.md


class GenerationStats(BaseModel):
    """Aggregate counters for a `generate` run."""

    total_groups: int = 0
    insufficient_groups: int = 0
    tasks_written: int = 0
    completions_received: int = 0
    skills_assembled: int = 0
    skills_validated: int = 0
    validation_failures: int = 0
    timed_out: int = 0
