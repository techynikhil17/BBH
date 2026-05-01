import pytest


@pytest.fixture
def tmp_db(tmp_path) -> str:
    return str(tmp_path / "test.db")
