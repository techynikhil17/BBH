"""Propagate confirmed chains to BOTH involved skill files.

For every confirmed chain in a session:
1. Write a forward-perspective entry into the ``from_skill``'s
   ATTACK CHAINS DISCOVERED section.
2. Write a reverse-perspective entry into the ``to_skill``'s
   ATTACK CHAINS DISCOVERED section.
3. Add / increment the chain in the shared knowledge graph.

The append uses the same atomic patcher mechanism the researcher agent uses
mid-session — that gives us identical formatting between live and post-
session updates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Iterable, Optional

from researcher.knowledge.graph_manager import ChainGraph
from researcher.session.models import ChainHypothesis, ChainStatus
from researcher.tools.skill_patcher import SkillPatcher, SkillPatcherError

from ..config import CHAIN_GRAPH_PATH, SKILLS_DIR


@dataclass
class PropagationResult:
    chains_propagated: int = 0
    skills_updated: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ChainPropagator:
    """Update both involved skills + the knowledge graph for each confirmed chain."""

    def __init__(
        self,
        skills_dir: Path = SKILLS_DIR,
        graph_path: Path = CHAIN_GRAPH_PATH,
        patcher: Optional[SkillPatcher] = None,
    ) -> None:
        self._skills_dir = Path(skills_dir)
        self._graph = ChainGraph(graph_path)
        self._patcher = patcher or SkillPatcher()

    def propagate(self, chains: Iterable[ChainHypothesis]) -> PropagationResult:
        result = PropagationResult()
        for chain in chains:
            if chain.status != ChainStatus.CONFIRMED:
                continue

            from_path = self._skill_md(chain.from_skill)
            to_path = self._skill_md(chain.to_skill)

            forward = self._with_perspective(chain, perspective="forward")
            reverse = self._with_perspective(chain, perspective="reverse")

            if from_path.exists():
                if self._safe_append(from_path, forward, result):
                    self._track(result, str(from_path))
            else:
                result.errors.append(
                    f"from_skill not found on disk: {from_path}"
                )

            if to_path.exists():
                if self._safe_append(to_path, reverse, result):
                    self._track(result, str(to_path))
            else:
                result.errors.append(
                    f"to_skill not found on disk: {to_path}"
                )

            self._graph.add_confirmed_chain(chain, session_id=chain.session_id)
            result.chains_propagated += 1

        return result

    # ---------- helpers ----------

    def _skill_md(self, skill_id: str) -> Path:
        """Resolve ``ssrf/cloud-metadata`` → ``skills/ssrf/cloud-metadata/skill.md``."""
        parts = [p for p in skill_id.split("/") if p]
        return self._skills_dir.joinpath(*parts, "skill.md")

    @staticmethod
    def _with_perspective(chain: ChainHypothesis, *, perspective: str) -> ChainHypothesis:
        """Return a chain copy with ``chain_name`` re-phrased per perspective."""
        today = date.today().isoformat()
        if perspective == "forward":
            new_name = f"{chain.chain_name} (forward, confirmed {today})"
        else:
            new_name = f"{chain.chain_name} (incoming chain, confirmed {today})"
        return chain.model_copy(update={"chain_name": new_name})

    def _safe_append(
        self,
        skill_path: Path,
        chain: ChainHypothesis,
        result: PropagationResult,
    ) -> bool:
        try:
            return self._patcher.append_chain(skill_path, chain)
        except SkillPatcherError as exc:
            result.errors.append(f"{skill_path}: {exc}")
            return False
        except OSError as exc:
            result.errors.append(f"{skill_path}: {exc}")
            return False

    @staticmethod
    def _track(result: PropagationResult, path: str) -> None:
        if path not in result.skills_updated:
            result.skills_updated.append(path)
