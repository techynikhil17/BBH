"""Structured observation input prompt.

Guides the user (or Claude Code in agentic mode) to record observations
with the fields the session logger needs. All input is text-only — no
payload entry, no command execution. The probe itself happens externally
(Burp / browser / curl) and the user types back the abstract observation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.prompt import Confirm, Prompt

from ..session.models import ObservationType


_TYPE_KEYS: dict[str, ObservationType] = {
    "p": ObservationType.POSITIVE,
    "n": ObservationType.NEGATIVE,
    "v": ObservationType.NOVEL,
    "c": ObservationType.CHAIN,
}


@dataclass
class ObservationInput:
    observation_type: ObservationType
    description: str
    probe_description: str
    chain_potential: Optional[str]
    record_failed: bool = False  # if True, treat as failed approach instead of observation
    failed_reason: str = ""


# What the human menu shows. (f) is intentionally separate from the type letters.
_PROMPT_HELP = (
    "Type: (p)ositive | (n)egative | no(v)el | (c)hain | (f)ailed approach | (q)uit"
)


def _ask_observation_type(console: Console) -> Optional[str]:
    """Block until the user picks a valid type letter, or returns 'f'/'q'."""
    valid = {"p", "n", "v", "c", "f", "q"}
    while True:
        console.print(_PROMPT_HELP, style="dim")
        raw = Prompt.ask("Type", default="p").strip().lower()
        if raw in valid:
            return raw
        console.print("[red]Invalid type. Choose one of p/n/v/c/f/q.[/red]")


async def collect_observation(console: Console) -> Optional[ObservationInput]:
    """Run the structured prompt loop. Returns ``None`` on quit."""
    return await asyncio.to_thread(_collect_observation_sync, console)


def _collect_observation_sync(console: Console) -> Optional[ObservationInput]:
    console.print()
    console.print("[bold cyan][OBSERVATION INPUT][/bold cyan]")

    raw_type = _ask_observation_type(console)
    if raw_type == "q":
        return None

    if raw_type == "f":
        approach = Prompt.ask("Approach (what you tried)").strip()
        reason = Prompt.ask("Why it failed").strip()
        return ObservationInput(
            observation_type=ObservationType.NEGATIVE,  # bookkeeping only
            description=approach,
            probe_description=approach,
            chain_potential=None,
            record_failed=True,
            failed_reason=reason,
        )

    description = Prompt.ask("Description (what you observed)").strip()
    probe = Prompt.ask("Probe used (brief, no payloads)").strip()

    chain_potential: Optional[str] = None
    has_chain_potential = Confirm.ask("Chain potential?", default=False)
    if has_chain_potential:
        chain_potential = Prompt.ask(
            "  → To which vuln class / target skill? (free text)"
        ).strip() or None

    return ObservationInput(
        observation_type=_TYPE_KEYS[raw_type],
        description=description,
        probe_description=probe,
        chain_potential=chain_potential,
    )
