from pathlib import Path

import pytest

from prowler.lib.check.models import CheckMetadata

PROVIDER_PATH = Path("prowler/providers/snowflake")
METADATA_FILES = sorted(PROVIDER_PATH.glob("services/**/*.metadata.json"))


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_snowflake_check_metadata_is_valid(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    assert metadata.Provider == "snowflake"
    assert metadata.CheckID == metadata_file.stem.replace(".metadata", "")


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_snowflake_checks_metadata_use_canonical_hub_urls(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    url = metadata.Remediation.Recommendation.Url
    assert not url.startswith("https://hub.prowler.com/checks/snowflake/"), (
        f"{metadata_file}: non-canonical hub URL {url}"
    )


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_snowflake_check_metadata_service_name_matches_its_folder(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    service_folder = metadata_file.relative_to(PROVIDER_PATH / "services").parts[0]
    assert metadata.ServiceName == service_folder


def test_snowflake_ships_at_least_one_check():
    assert METADATA_FILES
