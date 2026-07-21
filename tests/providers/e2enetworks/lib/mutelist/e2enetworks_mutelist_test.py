from unittest.mock import MagicMock

from prowler.providers.e2enetworks.lib.mutelist.mutelist import E2eNetworksMutelist


def _build_finding(check_id: str, location: str, resource_id: str, resource_name: str):
    finding = MagicMock()
    finding.check_metadata = MagicMock()
    finding.check_metadata.CheckID = check_id
    finding.status = "FAIL"
    finding.location = location
    finding.resource_id = resource_id
    finding.resource_name = resource_name
    finding.resource_tags = []
    return finding


class Test_e2enetworks_mutelist:
    def test_is_finding_muted(self):
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "node_public_ip_not_assigned": {
                            "Regions": ["Delhi"],
                            "Resources": ["example-node-id"],
                        }
                    }
                }
            }
        }

        mutelist = E2eNetworksMutelist(mutelist_content=mutelist_content)
        finding = _build_finding(
            "node_public_ip_not_assigned",
            "Delhi",
            "example-node-id",
            "example-node-id",
        )

        assert mutelist.is_finding_muted(finding=finding) is True

    def test_is_finding_not_muted_wrong_location(self):
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "node_public_ip_not_assigned": {
                            "Regions": ["Delhi"],
                            "Resources": ["example-node-id"],
                        }
                    }
                }
            }
        }

        mutelist = E2eNetworksMutelist(mutelist_content=mutelist_content)
        finding = _build_finding(
            "node_public_ip_not_assigned",
            "Mumbai",
            "example-node-id",
            "example-node-id",
        )

        assert mutelist.is_finding_muted(finding=finding) is False
