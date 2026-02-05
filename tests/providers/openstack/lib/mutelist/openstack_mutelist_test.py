from unittest.mock import MagicMock

import yaml

from prowler.providers.openstack.lib.mutelist.mutelist import OpenStackMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/openstack/lib/mutelist/fixtures/openstack_mutelist.yaml"
)


class TestOpenStackMutelist:
    def test_get_mutelist_file_from_local_file(self):
        """Test loading mutelist from a local file."""
        mutelist = OpenStackMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        """Test loading mutelist from a non-existent file."""
        mutelist_path = "tests/providers/openstack/lib/mutelist/fixtures/not_present"
        mutelist = OpenStackMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        """Test mutelist validation with invalid key."""
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = OpenStackMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted_by_resource_id(self):
        """Test finding is muted when matched by resource ID."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["ba6056d9-104a-4a22-afda-b68589ed9867"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_muted_by_resource_name(self):
        """Test finding is muted when matched by resource name."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_muted_by_resource_name_regex(self):
        """Test finding is muted when matched by resource name with regex pattern."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["test-.*"],  # Regex pattern
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance-1"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_not_muted(self):
        """Test finding is not muted when resource doesn't match."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["other-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert not mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_muted_with_wildcard_project(self):
        """Test finding is muted when using wildcard project ID."""
        mutelist_content = {
            "Accounts": {
                "*": {  # Wildcard for all projects
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "any-project-id")

    def test_is_finding_muted_with_wildcard_check(self):
        """Test finding is muted when using wildcard check name."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_*": {  # Wildcard for all compute checks
                            "Regions": ["*"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_muted_with_wildcard_resource(self):
        """Test finding is muted when using wildcard resource."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["*"],  # Wildcard for all resources
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "any-resource-id"
        finding.resource_name = "any-resource-name"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_muted_with_specific_region(self):
        """Test finding is muted when region matches."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["EU-WEST-PAR"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "EU-WEST-PAR"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_not_muted_with_different_region(self):
        """Test finding is not muted when region doesn't match."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["EU-WEST-PAR"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "US-EAST-1"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert not mutelist.is_finding_muted(finding, "test-project-id")

    def test_is_finding_not_muted_with_different_project(self):
        """Test finding is not muted when project ID doesn't match."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "compute_instance_security_groups_attached"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert not mutelist.is_finding_muted(finding, "different-project-id")

    def test_is_finding_not_muted_with_different_check(self):
        """Test finding is not muted when check ID doesn't match."""
        mutelist_content = {
            "Accounts": {
                "test-project-id": {
                    "Checks": {
                        "compute_instance_security_groups_attached": {
                            "Regions": ["*"],
                            "Resources": ["test-instance"],
                        }
                    }
                }
            }
        }

        mutelist = OpenStackMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "identity_password_policy_enabled"
        finding.region = "RegionOne"
        finding.status = "FAIL"
        finding.resource_id = "ba6056d9-104a-4a22-afda-b68589ed9867"
        finding.resource_name = "test-instance"
        finding.resource_tags = {}

        assert not mutelist.is_finding_muted(finding, "test-project-id")
