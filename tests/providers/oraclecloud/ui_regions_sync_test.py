import re
from pathlib import Path

from prowler.providers.oraclecloud.config import OCI_REGIONS

UI_REGIONS_FILE = (
    Path(__file__).resolve().parents[3]
    / "ui"
    / "lib"
    / "provider-credentials"
    / "oci-regions.ts"
)


def test_ui_home_region_list_matches_sdk_regions():
    ui_regions = set(
        re.findall(r'"([a-z]{2,3}-[a-z-]+-\d+)"', UI_REGIONS_FILE.read_text())
    )

    assert ui_regions == set(OCI_REGIONS)
