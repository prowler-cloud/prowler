from pathlib import Path

import pytest

from prowler.lib.check.models import CheckMetadata

EXPECTED_SERVICE_NAMES = {
    "administration": "administration",
    "compute": "compute",
    "networking": "networking",
}


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/linode").glob("services/**/*.metadata.json")),
)
def test_linode_check_metadata_is_valid(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    assert metadata.Provider == "linode"
    assert metadata.CheckID == metadata_file.stem.replace(".metadata", "")


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/linode").glob("services/**/*.metadata.json")),
)
def test_linode_checks_metadata_use_canonical_hub_urls(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    url = metadata.Remediation.Recommendation.Url
    assert not url.startswith(
        "https://hub.prowler.com/checks/linode/"
    ), f"{metadata_file}: non-canonical hub URL {url}"


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/linode").glob("services/**/*.metadata.json")),
)
def test_linode_check_metadata_uses_product_area_service_names(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    service_folder = metadata_file.relative_to(
        Path("prowler/providers/linode/services")
    ).parts[0]

    assert metadata.ServiceName == EXPECTED_SERVICE_NAMES[service_folder]
