import json

from generator.pipeline import grouper


def _pattern(url, vuln_class="ssrf", vuln_subtype="cloud-metadata", payout=1000.0, skipped=False):
    return {
        "source_url": url,
        "vuln_class": vuln_class,
        "vuln_subtype": vuln_subtype,
        "payout_usd": payout,
        "skipped": skipped,
        "preconditions": ["x"],
        "behavioral_signal": "y",
        "detection_approach": "z",
        "root_cause_pattern": "rcp",
    }


def test_grouping_basic():
    patterns = [
        _pattern("u1", "ssrf", "cloud-metadata"),
        _pattern("u2", "ssrf", "cloud-metadata"),
        _pattern("u3", "ssrf", "blind"),
        _pattern("u4", "ssrf", "blind"),
    ]
    eligible, insufficient = grouper.group_patterns(patterns, min_patterns=2)
    assert len(eligible) == 2
    keys = sorted((g.vuln_class, g.vuln_subtype) for g in eligible)
    assert keys == [("ssrf", "blind"), ("ssrf", "cloud-metadata")]
    assert insufficient == []


def test_groups_below_threshold_go_to_insufficient():
    patterns = [
        _pattern("u1", "ssrf", "cloud-metadata"),
        _pattern("u2", "ssrf", "cloud-metadata"),
        _pattern("u3", "rce", "ssti"),  # singleton — below threshold
    ]
    eligible, insufficient = grouper.group_patterns(patterns, min_patterns=2)
    assert len(eligible) == 1
    assert eligible[0].vuln_class == "ssrf"
    assert len(insufficient) == 1
    assert insufficient[0]["vuln_class"] == "rce"


def test_skipped_patterns_excluded():
    patterns = [
        _pattern("u1", skipped=True),
        _pattern("u2"),
        _pattern("u3"),
    ]
    eligible, _ = grouper.group_patterns(patterns, min_patterns=2)
    assert len(eligible) == 1
    assert len(eligible[0].patterns) == 2


def test_empty_vuln_class_excluded():
    patterns = [
        _pattern("u1", vuln_class="ssrf"),
        _pattern("u2", vuln_class="ssrf"),
        {"source_url": "u3", "vuln_class": "", "vuln_subtype": "x", "skipped": False, "preconditions": []},
    ]
    eligible, _ = grouper.group_patterns(patterns, min_patterns=2)
    assert sum(len(g.patterns) for g in eligible) == 2


def test_sort_by_pattern_count_then_payout():
    patterns = [
        # ssrf/blind: 3 patterns, avg payout 500
        _pattern("a1", "ssrf", "blind", 500),
        _pattern("a2", "ssrf", "blind", 500),
        _pattern("a3", "ssrf", "blind", 500),
        # rce/ssti: 2 patterns, avg payout 5000
        _pattern("b1", "rce", "ssti", 5000),
        _pattern("b2", "rce", "ssti", 5000),
        # idor/seq: 2 patterns, avg payout 1000
        _pattern("c1", "idor", "seq", 1000),
        _pattern("c2", "idor", "seq", 1000),
    ]
    eligible, _ = grouper.group_patterns(patterns, min_patterns=2)
    classes_in_order = [(g.vuln_class, g.vuln_subtype) for g in eligible]
    # ssrf/blind is first by count
    assert classes_in_order[0] == ("ssrf", "blind")
    # rce/ssti beats idor/seq because of higher payout (same count)
    assert classes_in_order[1] == ("rce", "ssti")
    assert classes_in_order[2] == ("idor", "seq")


def test_load_patterns_handles_malformed_lines(tmp_path):
    path = tmp_path / "p.jsonl"
    path.write_text(
        json.dumps({"source_url": "u1", "vuln_class": "ssrf"})
        + "\n"
        + "{not valid json\n"
        + json.dumps({"source_url": "u2", "vuln_class": "rce"})
        + "\n"
    )
    rows = grouper.load_patterns(path)
    assert len(rows) == 2


def test_load_patterns_missing_file(tmp_path):
    path = tmp_path / "nope.jsonl"
    rows = grouper.load_patterns(path)
    assert rows == []


def test_write_insufficient_patterns(tmp_path):
    out = tmp_path / "i.jsonl"
    written = grouper.write_insufficient_patterns(
        [{"source_url": "u1"}, {"source_url": "u2"}], out
    )
    assert written == 2
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2


def test_pattern_group_task_id_and_slug():
    g, _ = grouper.group_patterns(
        [_pattern("u1", "ssrf", "Cloud-Metadata"), _pattern("u2", "ssrf", "Cloud-Metadata")],
        min_patterns=2,
    )
    assert g[0].task_id == "skillgen_ssrf_cloud-metadata"
    assert g[0].slug == "cloud-metadata"
