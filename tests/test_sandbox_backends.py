import platform

import pytest

from sandbox.backends import SandboxUnavailable, require_verified_backend


def test_missing_native_helper_fails_closed(tmp_path):
    missing = tmp_path / ("missing.exe" if platform.system() == "Windows" else "missing")
    with pytest.raises(SandboxUnavailable, match="isolated plugins are disabled"):
        require_verified_backend(missing)

