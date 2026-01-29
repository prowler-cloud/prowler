from unittest.mock import MagicMock

import yaml

from prowler.providers.cloudflare.lib.mutelist.mutelist import CloudflareMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/cloudflare/lib/mutelist/fixtures/cloudflare_mutelist.yaml"
)


class TestCloudflareMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = CloudflareMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/cloudflare/lib/mutelist/fixtures/not_present"
        mutelist = CloudflareMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = CloudflareMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        mutelist_content = {
            "Accounts": {
                "test-account-id": {
                    "Checks": {
                        "zone_dnssec_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-zone-id"],
                        }
                    }
                }
            }
        }

        mutelist = CloudflareMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "zone_dnssec_enabled"
        finding.status = "FAIL"
        finding.resource_id = "test-zone-id"
        finding.resource_name = "example.com"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "test-account-id")

    def test_is_finding_not_muted(self):
        mutelist_content = {
            "Accounts": {
                "test-account-id": {
                    "Checks": {
                        "zone_dnssec_enabled": {
                            "Regions": ["*"],
                            "Resources": ["other-zone-id"],
                        }
                    }
                }
            }
        }

        mutelist = CloudflareMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "zone_dnssec_enabled"
        finding.status = "FAIL"
        finding.resource_id = "test-zone-id"
        finding.resource_name = "example.com"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding, "test-account-id")
