"""Local taxonomy classifier — pure normalization, no API calls.

Earlier versions of this module called Claude as a fallback when neither the
vuln class nor the feature type matched the canonical taxonomy. The
file-handoff build removes API access entirely; what remains is the local
alias-based normalization (see ``extractor.taxonomy``). The public surface
is preserved so downstream callers don't notice.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ..taxonomy import (
    normalize_feature_type,
    normalize_vuln_class,
)

logger = logging.getLogger(__name__)


class TaxonomyClassifier:
    """Normalize free-text vuln/feature labels to the canonical taxonomy.

    Local-only: looks the inputs up in ``VULN_ALIASES`` / ``FEATURE_ALIASES``.
    Anything that can't be normalized is returned lower-cased — caller flags
    as novel.
    """

    def __init__(
        self,
        # Compatibility kwargs — kept so previous call sites keep working.
        client: Any = None,
        model: Optional[str] = None,
        max_tokens: int = 200,
    ) -> None:
        self._max_tokens = max_tokens

    async def classify(
        self,
        raw_vuln_class: str,
        raw_feature_type: str,
        context: str = "",
    ) -> dict[str, str]:
        return {
            "vuln_class": normalize_vuln_class(raw_vuln_class),
            "feature_type": normalize_feature_type(raw_feature_type),
        }
