from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from ..models import RawReport

logger = logging.getLogger(__name__)


class AsyncCollector(ABC):
    source_name: str
    rate_limit_seconds: float = 2.0

    @abstractmethod
    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        ...

    async def _sleep(self) -> None:
        await asyncio.sleep(self.rate_limit_seconds)

    async def _retry(self, coro_fn, retries: int = 3):
        for attempt in range(retries):
            try:
                return await coro_fn()
            except Exception as exc:
                if attempt == retries - 1:
                    raise
                wait = 2 ** attempt
                logger.warning(
                    "%s retry %d/%d in %ds: %s",
                    self.source_name, attempt + 1, retries, wait, exc,
                )
                await asyncio.sleep(wait)
