import yaml
from mock import MagicMock

from prowler.providers.azure.lib.mutelist.mutelist import AzureMutelist
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

MUTELIST_FIXTURE_PATH = (
    "tests/providers/azure/lib/mutelist/fixtures/azure_mutelist.yaml"
)


class TestAzureMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = AzureMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = AzureMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = AzureMutelist(mutelist_content=mutelist_fixture)

        assert not mutelist.validate_mutelist()
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "subscription_1": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = AzureMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "check_test"
        finding.location = "West Europe"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.resource_tags = []
        finding.subscription = "subscription_1"

        assert mutelist.is_finding_muted(finding)

    def test_mute_finding(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "subscription_1": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = AzureMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="check_test",
            status="FAIL",
            account_uid="subscription_1",
            region="subscription_1",
            resource_uid="test_resource",
            resource_tags=[],
            muted=False,
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted is True
        assert muted_finding.raw["status"] == "FAIL"
