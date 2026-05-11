from unittest.mock import MagicMock

import yaml

from prowler.providers.okta.lib.mutelist.mutelist import OktaMutelist

MUTELIST_FIXTURE_PATH = "tests/providers/okta/lib/mutelist/fixtures/okta_mutelist.yaml"


class TestOktaMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = OktaMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/okta/lib/mutelist/fixtures/not_present"
        mutelist = OktaMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = OktaMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted_match(self):
        mutelist_content = {
            "Accounts": {
                "https://acme.okta.com": {
                    "Checks": {
                        "signon_global_session_idle_timeout_15min": {
                            "Regions": ["*"],
                            "Resources": ["pol-default"],
                        }
                    }
                }
            }
        }
        mutelist = OktaMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata.CheckID = "signon_global_session_idle_timeout_15min"
        finding.resource_name = "pol-default"
        finding.resource_tags = []

        assert (
            mutelist.is_finding_muted(finding, org_url="https://acme.okta.com") is True
        )

    def test_is_finding_muted_no_match(self):
        mutelist_content = {
            "Accounts": {
                "https://acme.okta.com": {
                    "Checks": {
                        "signon_global_session_idle_timeout_15min": {
                            "Regions": ["*"],
                            "Resources": ["pol-default"],
                        }
                    }
                }
            }
        }
        mutelist = OktaMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata.CheckID = "signon_global_session_idle_timeout_15min"
        finding.resource_name = "pol-other"
        finding.resource_tags = []

        assert (
            mutelist.is_finding_muted(finding, org_url="https://acme.okta.com") is False
        )
