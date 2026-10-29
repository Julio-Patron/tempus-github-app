from pathlib import Path

from tempus_github_app.errors import CORE_ERROR_CODES, LEGACY_ERROR_CODES


def test_legacy_codes_map_onto_tempus_ddb():
    assert LEGACY_ERROR_CODES
    assert set(LEGACY_ERROR_CODES.values()) <= CORE_ERROR_CODES


def test_legacy_codes_are_not_emitted():
    sources = Path("src/tempus_github_app")
    emitted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sources.glob("*.py")
        if path.name != "errors.py"
    )
    for legacy in LEGACY_ERROR_CODES:
        assert legacy not in emitted
