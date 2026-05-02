from unittest.mock import patch, MagicMock

from collector.sources.medium_rss import MediumRSSCollector


class FeedEntry:
    def __init__(self, title, link, author="", tags=None, published_parsed=None):
        self._d = {"title": title, "link": link, "summary": ""}
        self.author = author
        self.tags = [MagicMock(term=t) for t in (tags or [])]
        self.published_parsed = published_parsed or (2024, 3, 1, 0, 0, 0, 0, 0, 0)

    def get(self, key, default=""):
        return self._d.get(key, default)


def make_feed(entries):
    f = MagicMock()
    f.entries = entries
    return f


async def test_collects_from_all_three_feeds():
    feeds = [
        make_feed([FeedEntry("A", "https://medium.com/a")]),
        make_feed([FeedEntry("B", "https://medium.com/b")]),
        make_feed([FeedEntry("C", "https://medium.com/c")]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert len(reports) == 3
    urls = {r.url for r in reports}
    assert urls == {"https://medium.com/a", "https://medium.com/b", "https://medium.com/c"}


async def test_deduplicates_cross_feed_urls():
    same_url = "https://medium.com/shared"
    feeds = [
        make_feed([FeedEntry("Same A", same_url)]),
        make_feed([FeedEntry("Same B", same_url)]),
        make_feed([FeedEntry("Different", "https://medium.com/other")]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    urls = [r.url for r in reports]
    assert urls.count(same_url) == 1


async def test_deduplicates_cross_feed_query_variants():
    """The same Medium article appears in multiple tag feeds with different
    `?source=rss------<tag>-5` tracking params. Those should collapse to one."""
    base = "https://medium.com/@author/the-same-post-abc123"
    feeds = [
        make_feed([FeedEntry("Same", f"{base}?source=rss------bug_bounty-5")]),
        make_feed([FeedEntry("Same", f"{base}?source=rss------bugbounty-5")]),
        make_feed([FeedEntry("Same", f"{base}?gi=deadbeef&utm_source=feed")]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert len(reports) == 1


async def test_respects_limit():
    feeds = [
        make_feed([FeedEntry(f"A{i}", f"https://medium.com/a{i}") for i in range(10)]),
        make_feed([FeedEntry(f"B{i}", f"https://medium.com/b{i}") for i in range(10)]),
        make_feed([FeedEntry(f"C{i}", f"https://medium.com/c{i}") for i in range(10)]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(5)]

    assert len(reports) == 5


async def test_author_stored_in_source_metadata():
    feeds = [
        make_feed([FeedEntry("T", "https://medium.com/t", author="alice")]),
        make_feed([]),
        make_feed([]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert reports[0].source_metadata["author"] == "alice"


async def test_tolerates_feed_exception():
    from unittest.mock import MagicMock
    good_feed = make_feed([FeedEntry("OK", "https://medium.com/ok")])

    with patch(
        "collector.sources.medium_rss.feedparser.parse",
        side_effect=[Exception("network error"), good_feed, good_feed],
    ):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert any(r.url == "https://medium.com/ok" for r in reports)
