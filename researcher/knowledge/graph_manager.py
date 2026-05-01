"""Chain knowledge graph — persisted to ``researcher/knowledge/chain_graph.json``.

A flat, append-mostly structure:

    {
      "chains": [
        {
          "chain_name": "...",
          "from_skill": "ssrf/cloud-metadata",
          "to_skill": "auth/jwt-bypass",
          "frequency": 3,
          "confirmed_in_sessions": ["sess-a", "sess-b", "sess-c"],
          "trigger": "...",
          "combined_impact": "...",
          "first_seen": "2026-04-01",
          "last_seen": "2026-05-01"
        }
      ]
    }

Two chains are considered "the same" if they share ``(from_skill, to_skill)``
— we collapse semantically equivalent observations rather than letting the
graph explode with near-duplicates.
"""

from __future__ import annotations

import json
import threading
from datetime import date
from pathlib import Path
from typing import Any, Optional

from ..config import CHAIN_GRAPH_PATH
from ..session.models import ChainHypothesis


_LOCK = threading.Lock()


def _today() -> str:
    return date.today().isoformat()


def _empty_graph() -> dict[str, Any]:
    return {"chains": []}


class ChainGraph:
    """File-backed chain graph with simple-but-explicit JSON persistence."""

    def __init__(self, path: Path = CHAIN_GRAPH_PATH) -> None:
        self._path = Path(path)
        self._data: dict[str, Any] = _empty_graph()
        self._load()

    # ---------- persistence ----------

    def _load(self) -> None:
        if not self._path.exists():
            self._data = _empty_graph()
            return
        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
            if "chains" not in self._data or not isinstance(self._data["chains"], list):
                self._data = _empty_graph()
        except json.JSONDecodeError:
            self._data = _empty_graph()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self._path)

    # ---------- queries ----------

    def get_top_chains(self, top_n: int = 10) -> list[dict[str, Any]]:
        return sorted(self._data["chains"], key=lambda c: c.get("frequency", 0), reverse=True)[:top_n]

    def get_chain_suggestions(self, skill: str, top_n: int = 5) -> list[dict[str, Any]]:
        """Chains involving ``skill`` (as either side), ranked by frequency."""
        skill = (skill or "").strip().lower()
        if not skill:
            return []
        relevant = [
            c
            for c in self._data["chains"]
            if c.get("from_skill", "").lower() == skill or c.get("to_skill", "").lower() == skill
        ]
        # Ascribe a confidence label from frequency: 1 → low, 2 → medium, 3+ → high
        scored = [
            {
                **c,
                "confidence": (
                    "high" if c.get("frequency", 0) >= 3
                    else "medium" if c.get("frequency", 0) == 2
                    else "low"
                ),
            }
            for c in relevant
        ]
        scored.sort(key=lambda c: c.get("frequency", 0), reverse=True)
        return scored[:top_n]

    def get_skill_relationships(self, skill: str) -> dict[str, list[dict[str, Any]]]:
        """Return ``{outgoing: [...], incoming: [...]}`` for ``skill``."""
        skill = (skill or "").strip().lower()
        outgoing = [c for c in self._data["chains"] if c.get("from_skill", "").lower() == skill]
        incoming = [c for c in self._data["chains"] if c.get("to_skill", "").lower() == skill]
        return {"outgoing": outgoing, "incoming": incoming}

    # ---------- mutations ----------

    def add_confirmed_chain(self, chain: ChainHypothesis, session_id: Optional[str] = None) -> dict[str, Any]:
        """Add ``chain`` to the graph, collapsing duplicates by ``(from, to)``.

        Increments ``frequency`` and records the session ID. Returns the
        stored chain dict.
        """
        with _LOCK:
            from_skill = chain.from_skill.lower()
            to_skill = chain.to_skill.lower()
            sid = session_id or chain.session_id
            today = _today()

            for entry in self._data["chains"]:
                if (
                    entry.get("from_skill", "").lower() == from_skill
                    and entry.get("to_skill", "").lower() == to_skill
                ):
                    sessions = entry.setdefault("confirmed_in_sessions", [])
                    if sid not in sessions:
                        sessions.append(sid)
                        entry["frequency"] = len(sessions)
                    entry["last_seen"] = today
                    # Update narrative fields if the new chain has more info
                    for key in ("trigger", "pivot", "combined_impact", "chain_name"):
                        if not entry.get(key) and getattr(chain, key, None):
                            entry[key] = getattr(chain, key)
                    self._save()
                    return entry

            new_entry: dict[str, Any] = {
                "chain_name": chain.chain_name,
                "from_skill": chain.from_skill,
                "to_skill": chain.to_skill,
                "trigger": chain.trigger,
                "pivot": chain.pivot,
                "combined_impact": chain.combined_impact,
                "frequency": 1,
                "confirmed_in_sessions": [sid] if sid else [],
                "first_seen": today,
                "last_seen": today,
            }
            self._data["chains"].append(new_entry)
            self._save()
            return new_entry

    # ---------- rendering ----------

    def export_summary(self) -> str:
        rows = self.get_top_chains(top_n=15)
        lines = [
            "| From | To | Frequency | Last Seen | Combined Impact |",
            "|------|----|----------:|-----------|-----------------|",
        ]
        for r in rows:
            lines.append(
                f"| {r.get('from_skill', '-')} | {r.get('to_skill', '-')} | "
                f"{r.get('frequency', 0)} | {r.get('last_seen', '-')} | "
                f"{(r.get('combined_impact') or '-')[:60]} |"
            )
        if len(lines) == 2:
            lines.append("| _no chains recorded yet_ | | | | |")
        return "\n".join(lines)
