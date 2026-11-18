import pytest

from sentinel_inspector.database import Database


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "inspector.sqlite3")
    yield db
    db.engine.dispose()
