from pathlib import Path

import pytest

from prowler.lib.check.models import CheckMetadata


@pytest.mark.parametrize(
    "metadata_file",
    sorted(Path("prowler/providers/stackit").glob("services/**/*.metadata.json")),
)
def test_stackit_check_metadata_is_valid(metadata_file):
    metadata = CheckMetadata.parse_file(metadata_file)
    assert metadata.Provider == "stackit"
    assert metadata.CheckID == metadata_file.stem.replace(".metadata", "")
