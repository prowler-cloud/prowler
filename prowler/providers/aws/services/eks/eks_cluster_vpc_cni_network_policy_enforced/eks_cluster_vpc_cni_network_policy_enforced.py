import json
from typing import Optional

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client

VPC_CNI_ADDON_NAME = "vpc-cni"
NETWORK_POLICY_KEY = "enableNetworkPolicy"


def parse_configuration_values(configuration_values: Optional[str]) -> Optional[dict]:
    """Decode an EKS add-on `configurationValues` blob.

    Args:
        configuration_values: The raw JSON string returned by DescribeAddon, which is
            absent when no configuration has been supplied for the add-on.

    Returns:
        The decoded mapping, an empty mapping when nothing was supplied, or None when
        the blob is not a readable JSON object.
    """
    if not configuration_values:
        return {}
    try:
        configuration = json.loads(configuration_values)
    except ValueError:
        return None
    return configuration if isinstance(configuration, dict) else None


def boolean_configuration_value(value: object) -> Optional[bool]:
    """Read a VPC CNI boolean setting.

    The add-on configuration schema types these as a string carrying `"format": "boolean"`,
    so the API returns `"true"` rather than `true`; a JSON boolean is accepted as well
    because the schema is add-on-version specific and this blob is otherwise untyped.

    Args:
        value: The value found in the add-on configuration, if any.

    Returns:
        The boolean it denotes, or None when it is absent or not a recognized boolean.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


class eks_cluster_vpc_cni_network_policy_enforced(Check):
    """Ensure the Amazon VPC CNI add-on enforces Kubernetes network policies.

    Kubernetes NetworkPolicy resources live in the cluster and are not exposed by the
    EKS API. What the API does expose is whether the Amazon VPC CNI managed add-on has
    network policy enforcement switched on, which is the precondition for any
    NetworkPolicy to take effect.
    - PASS: The Amazon VPC CNI add-on sets enableNetworkPolicy to true.
    - FAIL: The Amazon VPC CNI add-on sets enableNetworkPolicy to false.
    - MANUAL: The setting cannot be read, or the cluster does not use the Amazon VPC CNI
      managed add-on.

    TWO WAYS A CLUSTER CAN ENFORCE NETWORK POLICIES WITHOUT THIS SETTING BEING TRUE, so a
    FAIL is a statement about the managed add-on and not about the cluster. Neither is
    fixable by reading more of the AWS API: both live in in-cluster state that
    DescribeAddon cannot see.

    1. A third-party policy engine. The EKS Best Practices Guide recommends Calico and
       Cilium for requirements the VPC CNI does not cover, such as Layer 7 and DNS
       hostname rules, in its "ThirdParty Network Policy Engines" section
       (https://docs.aws.amazon.com/eks/latest/best-practices/network-security.html).
       A cluster enforcing through one of those would correctly leave this setting false,
       because two enforcers are not run together.
    2. A self-managed VPC CNI. AWS documents three ways to enable the feature and only the
       first is visible here
       (https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html):
       `aws eks update-addon --addon-name vpc-cni` with configurationValues; `helm upgrade
       ... aws-vpc-cni`; or the `amazon-vpc-cni` ConfigMap key
       `enable-network-policy-controller: "true"` together with policy enforcement in the
       aws-node container of the VPC CNI DaemonSet. The second and third leave the EKS
       control plane with nothing to report.

    Detecting either is deliberately NOT attempted. Calico and Cilium are invisible to the
    AWS API, so any signal would be a guess presented as a measurement.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "MANUAL"
            addon = cluster.addons.get(VPC_CNI_ADDON_NAME)

            if addon is None and cluster.addons_discovery_failed:
                report.status_extended = f"EKS cluster {cluster.name} add-ons could not be listed, so Kubernetes network policy enforcement in the Amazon VPC CNI add-on cannot be determined."
            elif addon is None:
                report.status_extended = f"EKS cluster {cluster.name} does not use the Amazon VPC CNI managed add-on, so Kubernetes network policy enforcement cannot be determined from the EKS API. Review the self-managed CNI configuration in the cluster."
            elif addon.configuration_discovery_failed:
                report.status_extended = f"EKS cluster {cluster.name} Amazon VPC CNI add-on configuration could not be read, so Kubernetes network policy enforcement cannot be determined."
            else:
                configuration = parse_configuration_values(addon.configuration_values)
                if configuration is None:
                    report.status_extended = f"EKS cluster {cluster.name} Amazon VPC CNI add-on configuration values are not a readable JSON object, so Kubernetes network policy enforcement cannot be determined."
                else:
                    network_policy_enabled = boolean_configuration_value(
                        configuration.get(NETWORK_POLICY_KEY)
                    )
                    if network_policy_enabled is None:
                        report.status_extended = f"EKS cluster {cluster.name} Amazon VPC CNI add-on does not set {NETWORK_POLICY_KEY} to true or false, so Kubernetes network policy enforcement cannot be determined."
                    elif network_policy_enabled:
                        report.status = "PASS"
                        report.status_extended = f"EKS cluster {cluster.name} enforces Kubernetes network policies through the Amazon VPC CNI add-on. This does not confirm that NetworkPolicy resources restricting pod-to-pod traffic exist in the cluster."
                    else:
                        # States the measurement, not the inference from it. The previous wording --
                        # "cluster does not enforce Kubernetes network policies" -- claimed a cluster
                        # property from an add-on setting, and is false for a cluster enforcing
                        # through Calico or Cilium, or through a self-managed VPC CNI. Both are
                        # documented architectures rather than edge cases; see the class docstring.
                        report.status = "FAIL"
                        report.status_extended = f"EKS cluster {cluster.name} Amazon VPC CNI managed add-on does not enforce Kubernetes network policies, since it sets {NETWORK_POLICY_KEY} to false. Enforcement by a third-party policy engine or a self-managed VPC CNI is not visible to the EKS API and is not evaluated."

            findings.append(report)

        return findings
