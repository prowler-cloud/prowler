from pathlib import Path

import pytest

from prowler.lib.check.models import CheckMetadata

METADATA_FILES = sorted(
    Path("prowler/providers/huaweicloud").glob("services/**/*.metadata.json")
)


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_huaweicloud_check_metadata_is_valid(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    assert metadata.Provider == "huaweicloud"
    assert metadata.CheckID == metadata_file.stem.replace(".metadata", "")


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_huaweicloud_check_metadata_servicename_matches_folder(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    service_folder = metadata_file.relative_to(
        Path("prowler/providers/huaweicloud/services")
    ).parts[0]
    assert metadata.ServiceName == service_folder


@pytest.mark.parametrize("metadata_file", METADATA_FILES)
def test_huaweicloud_check_metadata_uses_canonical_hub_urls(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    url = metadata.Remediation.Recommendation.Url
    assert not url.startswith(
        "https://hub.prowler.com/checks/huaweicloud/"
    ), f"{metadata_file}: non-canonical hub URL {url}"
