import yaml
from mock import MagicMock

from prowler.providers.mongodbatlas.lib.mutelist.mutelist import MongoDBAtlasMutelist
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

MUTELIST_FIXTURE_PATH = (
    "tests/providers/mongodbatlas/lib/mutelist/fixtures/mongodbatlas_mutelist.yaml"
)


class TestMongoDBAtlasMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = MongoDBAtlasMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = MongoDBAtlasMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-cluster"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "clusters_authentication_enabled"
        finding.status = "FAIL"
        finding.resource_name = "test-cluster"
        finding.location = "*"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "68b188eb2c7c3f24d41bf0d8")

    def test_finding_is_not_muted_different_check(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-cluster"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "clusters_backup_enabled"  # Different check
        finding.status = "FAIL"
        finding.resource_name = "test-cluster"
        finding.location = "*"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding, "68b188eb2c7c3f24d41bf0d8")

    def test_finding_is_not_muted_different_resource(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-cluster"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "clusters_authentication_enabled"
        finding.status = "FAIL"
        finding.resource_name = "different-cluster"  # Different resource
        finding.location = "*"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding, "68b188eb2c7c3f24d41bf0d8")

    def test_finding_is_not_muted_different_account(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-cluster"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "clusters_authentication_enabled"
        finding.status = "FAIL"
        finding.resource_name = "test-cluster"
        finding.location = "*"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(
            finding, "different-org-id"
        )  # Different account

    def test_is_finding_muted_with_wildcard_account(self):
        # Mutelist with wildcard account
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "clusters_backup_enabled": {
                            "Regions": ["western_europe"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "clusters_backup_enabled"
        finding.status = "FAIL"
        finding.resource_name = "any-cluster"
        finding.location = "western_europe"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "any-org-id")

    def test_is_finding_muted_with_wildcard_resources(self):
        # Mutelist with wildcard resources
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "projects_auditing_enabled": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "projects_auditing_enabled"
        finding.status = "FAIL"
        finding.resource_name = "any-project"
        finding.location = "*"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "68b188eb2c7c3f24d41bf0d8")

    def test_mute_finding(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["test-cluster"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="clusters_authentication_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="test-cluster",
            resource_tags=[],
            service_name="clusters",
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted
        assert muted_finding.raw["status"] == "FAIL"

    def test_mute_finding_with_project_resource(self):
        # Mutelist for project resources
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "projects_auditing_enabled": {
                            "Regions": ["*"],
                            "Resources": ["production-project"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="projects_auditing_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="production-project",
            resource_tags=[],
            service_name="projects",
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted
        assert muted_finding.raw["status"] == "FAIL"

    def test_mute_finding_with_wildcard_check(self):
        # Mutelist with wildcard check
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="clusters_backup_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="any-cluster",
            resource_tags=[],
            service_name="clusters",
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted
        assert muted_finding.raw["status"] == "FAIL"

    def test_mute_finding_with_regex_resource_pattern(self):
        # Mutelist with regex resource pattern
        mutelist_content = {
            "Accounts": {
                "68b188eb2c7c3f24d41bf0d8": {
                    "Checks": {
                        "clusters_authentication_enabled": {
                            "Regions": ["*"],
                            "Resources": ["dev-.*", "test-.*"],
                        }
                    }
                }
            }
        }

        mutelist = MongoDBAtlasMutelist(mutelist_content=mutelist_content)

        # Test with dev- prefix
        finding_1 = generate_finding_output(
            check_id="clusters_authentication_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="dev-cluster-1",
            resource_tags=[],
            service_name="clusters",
        )

        muted_finding = mutelist.mute_finding(finding=finding_1)
        assert muted_finding.status == "MUTED"
        assert muted_finding.muted

        # Test with test- prefix
        finding_2 = generate_finding_output(
            check_id="clusters_authentication_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="test-cluster-1",
            resource_tags=[],
            service_name="clusters",
        )

        muted_finding = mutelist.mute_finding(finding=finding_2)
        assert muted_finding.status == "MUTED"
        assert muted_finding.muted

        # Test with prod- prefix (should not be muted)
        finding_3 = generate_finding_output(
            check_id="clusters_authentication_enabled",
            status="FAIL",
            account_uid="68b188eb2c7c3f24d41bf0d8",
            resource_uid="prod-cluster-1",
            resource_tags=[],
            service_name="clusters",
        )

        muted_finding = mutelist.mute_finding(finding=finding_3)
        assert muted_finding.status == "FAIL"  # Should not be muted
        assert not muted_finding.muted
