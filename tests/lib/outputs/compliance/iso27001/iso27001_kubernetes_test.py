from prowler.lib.check.compliance_models import (
    Compliance,
    Compliance_Requirement,
    ISO27001_2013_Requirement_Attribute,
)
from prowler.lib.outputs.compliance.iso27001.iso27001_kubernetes import (
    KubernetesISO27001,
)
from prowler.lib.outputs.compliance.iso27001.models import KubernetesISO27001Model
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.kubernetes.kubernetes_fixtures import (
    KUBERNETES_CLUSTER_NAME,
    KUBERNETES_NAMESPACE,
)


ISO27001_2013_KUBERNETES = Compliance(
    Framework="ISO27001",
    Name="ISO/IEC 27001 Information Security Management Standard 2013",
    Provider="Kubernetes",
    Version="2013",
    Description="ISO 27001 controls mapped to Kubernetes findings.",
    Requirements=[
        Compliance_Requirement(
            Id="A.10.1",
            Description="Protect Kubernetes workload configuration",
            Name="Cryptographic Controls",
            Attributes=[
                ISO27001_2013_Requirement_Attribute(
                    Category="A.10 Cryptography",
                    Objetive_ID="A.10.1",
                    Objetive_Name="Cryptographic Controls",
                    Check_Summary="Protect Kubernetes workload configuration",
                )
            ],
            Checks=["service_test_check_id"],
        ),
        Compliance_Requirement(
            Id="A.10.2",
            Description="Manual Kubernetes control",
            Name="Cryptographic Controls",
            Attributes=[
                ISO27001_2013_Requirement_Attribute(
                    Category="A.10 Cryptography",
                    Objetive_ID="A.10.2",
                    Objetive_Name="Cryptographic Controls",
                    Check_Summary="Manual Kubernetes control",
                )
            ],
            Checks=[],
        ),
    ],
)


class TestKubernetesISO27001:
    def test_output_transform_includes_cluster(self):
        findings = [
            generate_finding_output(
                provider="kubernetes",
                compliance={"ISO27001-2013": "A.10.1"},
                account_name="context: kind-dev",
                account_uid=KUBERNETES_CLUSTER_NAME,
                region=KUBERNETES_NAMESPACE,
            )
        ]

        output = KubernetesISO27001(findings, ISO27001_2013_KUBERNETES)

        output_data = output.data[0]
        assert isinstance(output_data, KubernetesISO27001Model)
        assert output_data.Context == "context: kind-dev"
        assert output_data.Cluster == KUBERNETES_CLUSTER_NAME
        assert output_data.Namespace == KUBERNETES_NAMESPACE

        manual = output.data[1]
        assert manual.Context == ""
        assert manual.Cluster == ""
        assert manual.Namespace == ""
