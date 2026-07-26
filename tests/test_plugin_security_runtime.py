from pipeline.database import Database
from runtime.plugin_security import build_plugin_security


def test_runtime_fails_closed_without_native_helper(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    runtime = build_plugin_security(
        db, artifact_root=tmp_path / "artifacts",
        helper=tmp_path / "missing-helper")
    assert not runtime.isolated_plugins_available
    assert runtime.workers is None
    assert runtime.backend_probe.verified is False

