from unittest import mock

import pytest

from prowler.providers.aws.services.eks.eks_service import EKSAddon, EKSCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

cluster_name = "cluster_test"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)
addon_arn = f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:addon/{cluster_name}/vpc-cni/1a2b3c4d"


def build_cluster(name=cluster_name, arn=cluster_arn, **kwargs):
    """Build an EKSCluster whose add-on state the caller supplies through kwargs.

    The defaults leave `addons` empty and both discovery flags false, which is the shape of a
    cluster that carries no managed add-ons rather than one whose add-ons could not be read.
    """
    return EKSCluster(name=name, arn=arn, region=AWS_REGION_EU_WEST_1, **kwargs)


def vpc_cni_addon(configuration_values=None, configuration_discovery_failed=False):
    """Build the `addons` mapping for a cluster carrying the vpc-cni managed add-on.

    `configuration_values` is passed through as the raw JSON string DescribeAddon returns, so a
    test can supply the exact blob the API would, including an absent or malformed one.
    """
    return {
        "vpc-cni": EKSAddon(
            name="vpc-cni",
            arn=addon_arn,
            configuration_values=configuration_values,
            configuration_discovery_failed=configuration_discovery_failed,
        )
    }


def run_check(clusters):
    """Execute the check against the given clusters and return its reports.

    The clusters are model objects, so the reports exercise the check's own branching over
    already-collected state and no EKS API call takes place.
    """
    eks_client = mock.MagicMock
    eks_client.clusters = clusters
    with mock.patch(
        "prowler.providers.aws.services.eks.eks_service.EKS",
        eks_client,
    ):
        from prowler.providers.aws.services.eks.eks_cluster_vpc_cni_network_policy_enforced.eks_cluster_vpc_cni_network_policy_enforced import (
            eks_cluster_vpc_cni_network_policy_enforced,
        )

        return eks_cluster_vpc_cni_network_policy_enforced().execute()


class Test_eks_cluster_vpc_cni_network_policy_enforced:
    def test_no_clusters(self):
        """An account with no EKS clusters must produce no reports at all."""
        assert len(run_check([])) == 0

    def test_addons_discovery_failed(self):
        """A cluster whose ListAddons call failed must be MANUAL, not FAIL.

        The add-on mapping is empty in both this case and the no-managed-add-on case, so the
        cluster-level flag is what separates "unknown" from "not installed".
        """
        result = run_check([build_cluster(addons_discovery_failed=True)])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} add-ons could not be listed, so Kubernetes "
            "network policy enforcement in the Amazon VPC CNI add-on cannot be determined."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_no_vpc_cni_addon(self):
        """A cluster with managed add-ons but no vpc-cni must be MANUAL and name the CNI.

        The EKS API exposes nothing about a CNI it does not manage, so the verdict cannot be
        FAIL: the cluster may well enforce network policies through a self-managed CNI.
        """
        result = run_check(
            [build_cluster(addons={"coredns": EKSAddon(name="coredns")})]
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} does not use the Amazon VPC CNI managed "
            "add-on, so Kubernetes network policy enforcement cannot be determined "
            "from the EKS API. Review the self-managed CNI configuration in the cluster."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_addons_listed_but_empty(self):
        """A cluster whose add-ons listed successfully as empty must get the not-installed wording.

        Same MANUAL verdict as a failed listing but a different explanation, so the report does
        not tell an operator to fix permissions when the add-on is simply not there.
        """
        result = run_check([build_cluster(addons={})])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} does not use the Amazon VPC CNI managed "
            "add-on, so Kubernetes network policy enforcement cannot be determined "
            "from the EKS API. Review the self-managed CNI configuration in the cluster."
        )

    def test_addon_configuration_unreadable(self):
        """A vpc-cni add-on whose DescribeAddon call failed must be MANUAL.

        The add-on is known to be installed, but its configuration was never read, so network
        policy enforcement is undetermined rather than off.
        """
        result = run_check(
            [build_cluster(addons=vpc_cni_addon(configuration_discovery_failed=True))]
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} Amazon VPC CNI add-on configuration could "
            "not be read, so Kubernetes network policy enforcement cannot be determined."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_addon_configuration_unreadable_wins_over_stale_values(self):
        """A failed describe must stay MANUAL even when the model still carries a true setting.

        Guards the branch order: reading `configuration_values` before checking the failure flag
        would report PASS from a value the failed call did not return.
        """
        result = run_check(
            [
                build_cluster(
                    addons=vpc_cni_addon(
                        configuration_values='{"enableNetworkPolicy":"true"}',
                        configuration_discovery_failed=True,
                    )
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} Amazon VPC CNI add-on configuration could "
            "not be read, so Kubernetes network policy enforcement cannot be determined."
        )

    @pytest.mark.parametrize(
        "configuration_values",
        ['{"enableNetworkPolicy": "true"', '["enableNetworkPolicy"]', "true", "42"],
    )
    def test_addon_configuration_not_a_json_object(self, configuration_values):
        """Configuration values that do not decode to a JSON object must be MANUAL.

        Truncated JSON, an array, a bare boolean and a bare number each reach a different line of
        the decoder, and none may raise out of the check or be read as an empty configuration.
        """
        result = run_check([build_cluster(addons=vpc_cni_addon(configuration_values))])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} Amazon VPC CNI add-on configuration values "
            "are not a readable JSON object, so Kubernetes network policy enforcement "
            "cannot be determined."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    @pytest.mark.parametrize(
        "configuration_values",
        [
            None,
            "",
            "{}",
            '{"enableWindowsIpam": "false"}',
            '{"enableNetworkPolicy": "yes"}',
            '{"enableNetworkPolicy": 1}',
            '{"enableNetworkPolicy": null}',
        ],
    )
    def test_network_policy_setting_not_a_boolean(self, configuration_values):
        """A configuration carrying no recognizable boolean for the setting must be MANUAL, never FAIL.

        Absent, empty, a different key, `"yes"`, `1` and `null` all mean the setting was not
        stated. Reporting FAIL on any of them would assert that enforcement is off on the strength
        of a value the API never returned.
        """
        result = run_check([build_cluster(addons=vpc_cni_addon(configuration_values))])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} Amazon VPC CNI add-on does not set "
            "enableNetworkPolicy to true or false, so Kubernetes network policy "
            "enforcement cannot be determined."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    @pytest.mark.parametrize(
        "configuration_values",
        [
            '{"enableNetworkPolicy": "true"}',
            '{"enableNetworkPolicy": "True"}',
            '{"enableNetworkPolicy": true}',
            '{"enableNetworkPolicy": "true", "enableWindowsIpam": "false"}',
        ],
    )
    def test_network_policy_enforced(self, configuration_values):
        """A cluster whose vpc-cni add-on enables the setting must PASS, string or boolean.

        The add-on configuration schema types this setting as a string carrying
        `"format": "boolean"`, so the API returns `"true"` rather than `true`; `"True"` and a JSON
        boolean must land on the same verdict, and an unrelated sibling key must not disturb it.
        """
        result = run_check([build_cluster(addons=vpc_cni_addon(configuration_values))])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} enforces Kubernetes network policies through "
            "the Amazon VPC CNI add-on. This does not confirm that NetworkPolicy "
            "resources restricting pod-to-pod traffic exist in the cluster."
        )
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    @pytest.mark.parametrize(
        "configuration_values",
        [
            '{"enableNetworkPolicy": "false"}',
            '{"enableNetworkPolicy": "False"}',
            '{"enableNetworkPolicy": false}',
        ],
    )
    def test_network_policy_not_enforced(self, configuration_values):
        """A cluster whose vpc-cni add-on sets the setting to false must FAIL, string or boolean.

        `"false"`, `"False"` and a JSON `false` are the three forms the setting can arrive in, and
        a decoder that only understood one of them would report MANUAL on a real misconfiguration.
        """
        result = run_check([build_cluster(addons=vpc_cni_addon(configuration_values))])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"EKS cluster {cluster_name} Amazon VPC CNI managed add-on does not enforce "
            "Kubernetes network policies, since it sets enableNetworkPolicy to false. "
            "Enforcement by a third-party policy engine or a self-managed VPC CNI is not "
            "visible to the EKS API and is not evaluated."
        )
        # The finding must not claim a property of the CLUSTER from an add-on setting: a cluster
        # enforcing through Calico or Cilium, or through a self-managed VPC CNI, has this setting
        # false and does enforce. Both are documented architectures, so the old wording was false
        # of them rather than merely imprecise.
        assert "cluster does not enforce" not in result[0].status_extended
        assert result[0].resource_id == cluster_name
        assert result[0].resource_arn == cluster_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_multiple_clusters(self):
        """Six clusters must yield six reports, in input order, each judged on its own add-on.

        Two enforcing, three not and one with no managed add-on, so a check that carried state
        between iterations or reported once per account would not produce this split.
        """
        clusters = []
        for index in range(6):
            name = f"{cluster_name}_{index}"
            arn = f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{name}"
            if index in (0, 1):
                addons = vpc_cni_addon('{"enableNetworkPolicy": "true"}')
            elif index in (2, 3, 4):
                addons = vpc_cni_addon('{"enableNetworkPolicy": "false"}')
            else:
                addons = {}
            clusters.append(build_cluster(name=name, arn=arn, addons=addons))

        result = run_check(clusters)

        assert len(result) == 6
        statuses = [report.status for report in result]
        assert statuses.count("PASS") == 2
        assert statuses.count("FAIL") == 3
        assert statuses.count("MANUAL") == 1
        assert [report.resource_id for report in result] == [
            f"{cluster_name}_{index}" for index in range(6)
        ]
