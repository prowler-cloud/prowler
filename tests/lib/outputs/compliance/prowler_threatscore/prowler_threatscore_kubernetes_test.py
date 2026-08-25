from prowler.lib.check.compliance_models import (
    Compliance,
    Compliance_Requirement,
    Prowler_ThreatScore_Requirement_Attribute,
)
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreKubernetesModel,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_kubernetes import (
    ProwlerThreatScoreKubernetes,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.kubernetes.kubernetes_fixtures import (
    KUBERNETES_CLUSTER_NAME,
    KUBERNETES_NAMESPACE,
)

PROWLER_THREATSCORE_KUBERNETES = Compliance(
    Framework="ProwlerThreatScore",
    Name="Prowler ThreatScore Compliance Framework for Kubernetes",
    Version="1.0",
    Provider="Kubernetes",
    Description="Prowler ThreatScore controls mapped to Kubernetes findings.",
    Requirements=[
        Compliance_Requirement(
            Id="1.1.1",
            Description="Kubernetes workload hardening",
            Attributes=[
                Prowler_ThreatScore_Requirement_Attribute(
                    Title="Workload hardening",
                    Section="1. Kubernetes",
                    SubSection="1.1 Workloads",
                    AttributeDescription="Kubernetes workload hardening control.",
                    AdditionalInformation="",
                    LevelOfRisk=5,
                    Weight=1000,
                )
            ],
            Checks=["service_test_check_id"],
        ),
        Compliance_Requirement(
            Id="1.1.2",
            Description="Manual Kubernetes review",
            Attributes=[
                Prowler_ThreatScore_Requirement_Attribute(
                    Title="Manual review",
                    Section="1. Kubernetes",
                    SubSection="1.1 Workloads",
                    AttributeDescription="Manual Kubernetes review control.",
                    AdditionalInformation="",
                    LevelOfRisk=3,
                    Weight=10,
                )
            ],
            Checks=[],
        ),
    ],
)


class TestProwlerThreatScoreKubernetes:
    def test_output_transform_includes_cluster(self):
        findings = [
            generate_finding_output(
                provider="kubernetes",
                compliance={"ProwlerThreatScore-1.0": "1.1.1"},
                account_name="context: kind-dev",
                account_uid=KUBERNETES_CLUSTER_NAME,
                region=KUBERNETES_NAMESPACE,
            )
        ]

        output = ProwlerThreatScoreKubernetes(findings, PROWLER_THREATSCORE_KUBERNETES)

        output_data = output.data[0]
        assert isinstance(output_data, ProwlerThreatScoreKubernetesModel)
        assert output_data.Context == "context: kind-dev"
        assert output_data.Cluster == KUBERNETES_CLUSTER_NAME
        assert output_data.Namespace == KUBERNETES_NAMESPACE

        manual = output.data[1]
        assert manual.Context == ""
        assert manual.Cluster == ""
        assert manual.Namespace == ""
