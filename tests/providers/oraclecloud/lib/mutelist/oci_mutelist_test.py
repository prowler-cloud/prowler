from unittest.mock import MagicMock

import yaml

from prowler.lib.outputs.finding import Finding
from prowler.providers.oraclecloud.lib.mutelist.mutelist import OCIMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/oraclecloud/lib/mutelist/fixtures/oci_mutelist.yaml"
)


def generate_oci_finding_output(**kwargs):
    """Generate a Finding object for OCI testing"""
    return Finding(**kwargs)


class TestOCIMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = OCIMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = OCIMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = OCIMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "ocid1.tenancy.oc1..tenancy1": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = OCIMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "check_test"
        finding.status = "FAIL"
        finding.resource_id = "test_resource"
        finding.region = "us-ashburn-1"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "ocid1.tenancy.oc1..tenancy1")
