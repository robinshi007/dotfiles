import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet


@pytest.mark.parametrize(
    ("version", "supported"),
    [
        ("3.14.9", False),
        ("3.15.0rc1", True),
        ("3.15.0", True),
        ("3.15.99", True),
        ("3.16.0a1", False),
        ("3.16.0", False),
    ],
)
def test_supported_python_versions(version: str, supported: bool) -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as file:
        requires_python = tomllib.load(file)["project"]["requires-python"]

    assert SpecifierSet(requires_python).contains(version, prereleases=True) is supported
