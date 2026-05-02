from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from collector.main import cli


def make_mock_storage():
    storage = AsyncMock()
    storage.__aenter__ = AsyncMock(return_value=storage)
    storage.__aexit__ = AsyncMock(return_value=False)
    storage.save_report = AsyncMock(return_value=True)
    storage.get_stats = AsyncMock(return_value={"hackerone": 5, "total": 5})
    storage.export_to_jsonl = AsyncMock(return_value=5)
    return storage


def test_stats_command():
    mock_storage = make_mock_storage()
    with patch("collector.main.Storage", return_value=mock_storage):
        runner = CliRunner()
        result = runner.invoke(cli, ["stats"])
    assert result.exit_code == 0
    assert "hackerone" in result.output


def test_export_command(tmp_path):
    out = str(tmp_path / "out.jsonl")
    mock_storage = make_mock_storage()
    with patch("collector.main.Storage", return_value=mock_storage):
        runner = CliRunner()
        result = runner.invoke(cli, ["export", "--output", out])
    assert result.exit_code == 0
    assert "5" in result.output


def test_collect_all_sources():
    async def empty_collect(limit):
        return
        yield  # make it an async generator

    mock_collector = MagicMock()
    mock_collector.collect = empty_collect
    mock_storage = make_mock_storage()

    with patch("collector.main.Storage", return_value=mock_storage):
        with patch("collector.main.get_collector", return_value=mock_collector):
            runner = CliRunner()
            result = runner.invoke(cli, ["collect", "--sources", "medium", "--limit", "10"])
    assert result.exit_code == 0


def test_collect_invalid_source():
    runner = CliRunner()
    result = runner.invoke(cli, ["collect", "--sources", "notasource", "--limit", "5"])
    assert result.exit_code != 0 or "error" in result.output.lower()


def test_deprecated_sources_rejected():
    """Bugcrowd and Pentesterland are deprecated upstream sources — they're
    no longer registered in _COLLECTORS, so the CLI should reject them with
    the same "Unknown source" error as a typo."""
    runner = CliRunner()
    for source in ("bugcrowd", "pentesterland"):
        result = runner.invoke(cli, ["collect", "--sources", source, "--limit", "5"])
        assert result.exit_code != 0, f"expected {source!r} to be rejected"
