import yaml
from mock import MagicMock

from prowler.providers.kubernetes.lib.mutelist.mutelist import KubernetesMutelist
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

MUTELIST_FIXTURE_PATH = (
    "tests/providers/kubernetes/lib/mutelist/fixtures/kubernetes_mutelist.yaml"
)


class TestKubernetesMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = KubernetesMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = KubernetesMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = KubernetesMutelist(mutelist_content=mutelist_fixture)

        assert not mutelist.validate_mutelist()
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "cluster_1": {
                    "Checks": {
                        "check_test": {
                            # TODO: review this with Sergio
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = KubernetesMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "check_test"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.namespace = "test-location"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "cluster_1")

    def test_is_finding_muted_apiserver_star_within_check_name_with_exception(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "apiserver_*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Exceptions": {
                                "Accounts": ["cluster_1"],
                                "Regions": ["namespace1", "namespace2"],
                            },
                        }
                    }
                }
            }
        }

        mutelist = KubernetesMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "apiserver_etcd_cafile_set"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.namespace = "namespace1"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding, "cluster_1")

    def test_is_finding_muted_apiserver_star_within_check_name(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "apiserver_*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Exceptions": {
                                "Accounts": ["k8s-cluster-1"],
                                "Regions": ["namespace1", "namespace2"],
                            },
                        }
                    }
                }
            }
        }

        mutelist = KubernetesMutelist(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "apiserver_etcd_cafile_set"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.namespace = "namespace1"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "cluster_1")

    def test_mute_finding(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "cluster_1": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = KubernetesMutelist(mutelist_content=mutelist_content)

        finding_1 = generate_finding_output(
            check_id="check_test",
            status="FAIL",
            account_uid="cluster_1",
            region="test-region",
            resource_uid="test_resource",
            resource_tags=[],
            muted=False,
        )

        muted_finding = mutelist.mute_finding(finding_1)

        assert muted_finding.status == "MUTED"
        assert muted_finding.muted is True
        assert muted_finding.raw["status"] == "FAIL"
