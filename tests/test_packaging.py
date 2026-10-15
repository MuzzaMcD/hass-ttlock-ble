"""The ttlock-ble SDK ships bundled inside the integration, not from PyPI."""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_COMPONENT = _ROOT / "custom_components" / "hass_ttlock_ble"
_BUNDLED = _COMPONENT / "ttlock_ble"


def test_manifest_does_not_install_the_sdk() -> None:
    """Home Assistant must not install ttlock-ble from PyPI.

    The integration imports its bundled copy, so a manifest requirement on the
    package would only install an unused (and possibly different) release.
    """
    manifest = json.loads((_COMPONENT / "manifest.json").read_text())
    names = [
        re.split(r"[\s=<>!~@\[;]", req, maxsplit=1)[0]
        for req in manifest["requirements"]
    ]
    assert "ttlock-ble" not in names
    assert "ttlock_ble" not in names


def test_sdk_is_bundled() -> None:
    """scripts/bundle_ttlock_ble has been run and copied the package in."""
    assert (_BUNDLED / "__init__.py").is_file()


def test_integration_never_imports_an_installed_sdk() -> None:
    """Every SDK import must be relative, so it resolves to the bundled copy.

    An absolute `from ttlock_ble import …` would silently pick up any release
    left installed in Home Assistant's environment instead.
    """
    absolute = re.compile(r"^\s*(from|import)\s+ttlock_ble\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(_ROOT))
        for path in _COMPONENT.rglob("*.py")
        if _BUNDLED not in path.parents and absolute.search(path.read_text())
    ]
    assert offenders == []
