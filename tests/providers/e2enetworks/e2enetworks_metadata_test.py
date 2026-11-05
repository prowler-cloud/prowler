from pathlib import Path

import pytest

from prowler.lib.check.models import CheckMetadata

EXPECTED_SERVICE_NAMES = {
    "database": "database",
    "loadbalancer": "loadbalancer",
    "network": "network",
    "node": "node",
    "securitygroup": "securitygroup",
    "storage": "storage",
}


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/e2enetworks").glob("services/**/*.metadata.json")),
)
def test_e2enetworks_check_metadata_is_valid(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    assert metadata.Provider == "e2enetworks"
    assert metadata.CheckID == metadata_file.stem.replace(".metadata", "")


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/e2enetworks").glob("services/**/*.metadata.json")),
)
def test_e2enetworks_check_metadata_uses_service_folder_names(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    service_folder = metadata_file.relative_to(
        Path("prowler/providers/e2enetworks/services")
    ).parts[0]

    assert metadata.ServiceName == EXPECTED_SERVICE_NAMES[service_folder]
