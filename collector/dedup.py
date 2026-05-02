import hashlib
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Strip query and fragment so cross-feed variants collapse.

    Medium serves the same article through multiple tag feeds with
    `?source=rss------bug_bounty-5` style suffixes — those are tracking
    params, not distinct articles. Normalizing to scheme+host+path lets
    dedup catch them.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def url_hash(url: str) -> str:
    return hashlib.sha256(normalize_url(url).encode()).hexdigest()
