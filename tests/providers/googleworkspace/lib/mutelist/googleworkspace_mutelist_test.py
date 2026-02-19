import yaml
from mock import MagicMock

from prowler.providers.googleworkspace.lib.mutelist.mutelist import (
    GoogleWorkspaceMutelist,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

MUTELIST_FIXTURE_PATH = "tests/providers/googleworkspace/lib/mutelist/fixtures/googleworkspace_mutelist.yaml"


class TestGoogleWorkspaceMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = GoogleWorkspaceMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = GoogleWorkspaceMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = GoogleWorkspaceMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        mutelist_content = {
            "Accounts": {
                "C1234567": {
                    "Checks": {
                        "directory_super_admin_count": {
                            "Regions": ["*"],
                            "Resources": ["test-company.com"],
                        }
                    }
                }
            }
        }

        mutelist = GoogleWorkspaceMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "directory_super_admin_count"
        finding.status = "FAIL"
        finding.customer_id = "C1234567"
        finding.location = "global"
        finding.resource_name = "test-company.com"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding)

    def test_is_finding_not_muted(self):
        mutelist_content = {
            "Accounts": {
                "C1234567": {
                    "Checks": {
                        "directory_super_admin_count": {
                            "Regions": ["*"],
                            "Resources": ["test-company.com"],
                        }
                    }
                }
            }
        }

        mutelist = GoogleWorkspaceMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "directory_super_admin_count"
        finding.status = "FAIL"
        finding.customer_id = "C9999999"
        finding.location = "global"
        finding.resource_name = "test-company.com"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding)

    def test_mute_finding(self):
        mutelist_content = {
            "Accounts": {
                "C1234567": {
                    "Checks": {
                        "directory_super_admin_count": {
                            "Regions": ["*"],
                            "Resources": ["test-company.com"],
                        }
                    }
                }
            }
        }

        mutelist = GoogleWorkspaceMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="directory_super_admin_count",
            service_name="directory",
            status="FAIL",
            account_uid="C1234567",
            region="global",
            resource_uid="test-company.com",
            resource_tags={},
            muted=False,
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted
        assert muted_finding.raw["status"] == "FAIL"
