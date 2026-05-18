"""Drift checks for the API version constants.

Guarantee that ``config.version`` always reflects the canonical
``[project].version`` declared in ``api/pyproject.toml``.
"""

import tomllib
from pathlib import Path

import pytest
from config import version as config_version


@pytest.fixture(scope="module")
def pyproject_data():
    here = Path(__file__).resolve()
    for directory in here.parents:
        candidate = directory / "pyproject.toml"
        if not candidate.is_file():
            continue
        with candidate.open("rb") as f:
            data = tomllib.load(f)
        if data.get("project", {}).get("name") == "prowler-api":
            return data
    pytest.fail("api/pyproject.toml not reachable from the test runner")


def test_release_id_matches_pyproject(pyproject_data):
    assert config_version.RELEASE_ID == pyproject_data["project"]["version"]


def test_api_version_is_major_of_release_id():
    assert config_version.API_VERSION == config_version.RELEASE_ID.split(".", 1)[0]
    assert config_version.API_VERSION.isdigit()


def test_api_version_matches_v1_url_prefix():
    # The public contract version surfaced in the health payload must match
    # the URL namespace the API is published under.
    assert config_version.API_VERSION == "1"
