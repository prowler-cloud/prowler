from unittest import mock

from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    CIS_Requirement_Attribute_AssessmentStatus,
    CIS_Requirement_Attribute_Profile,
    Compliance,
    Compliance_Requirement,
)
from prowler.lib.check.models import CheckMetadata


class TestCompliance:

    def get_custom_framework(self):
        return {
            "framework1_aws": Compliance(
                Framework="Framework1",
                Provider="aws",
                Version="1.0",
                Description="Framework 1 Description",
                Requirements=[
                    Compliance_Requirement(
                        Id="1.1.1",
                        Description="description",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="1. Identity",
                                Profile=CIS_Requirement_Attribute_Profile("Level 1"),
                                AssessmentStatus=CIS_Requirement_Attribute_AssessmentStatus(
                                    "Manual"
                                ),
                                Description="Description",
                                RationaleStatement="Rationale",
                                ImpactStatement="Impact",
                                RemediationProcedure="Remediation",
                                AuditProcedure="Audit",
                                AdditionalInformation="Additional",
                                References="References",
                            )
                        ],
                        Checks=["check1", "check2"],
                    ),
                    # Manual requirement
                    Compliance_Requirement(
                        Id="1.1.2",
                        Description="description",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="1. Identity",
                                Profile=CIS_Requirement_Attribute_Profile("Level 1"),
                                AssessmentStatus=CIS_Requirement_Attribute_AssessmentStatus(
                                    "Manual"
                                ),
                                Description="Description",
                                RationaleStatement="Rationale",
                                ImpactStatement="Impact",
                                RemediationProcedure="Remediation",
                                AuditProcedure="Audit",
                                AdditionalInformation="Additional",
                                References="References",
                            )
                        ],
                        Checks=[],
                    ),
                ],
            ),
            "framework1_azure": Compliance(
                Framework="Framework1",
                Provider="azure",
                Version="1.0",
                Description="Framework 2 Description",
                Requirements=[
                    Compliance_Requirement(
                        Id="1.1.1",
                        Description="description",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="1. Identity",
                                Profile=CIS_Requirement_Attribute_Profile("Level 1"),
                                AssessmentStatus=CIS_Requirement_Attribute_AssessmentStatus(
                                    "Manual"
                                ),
                                Description="Description",
                                RationaleStatement="Rationale",
                                ImpactStatement="Impact",
                                RemediationProcedure="Remediation",
                                AuditProcedure="Audit",
                                AdditionalInformation="Additional",
                                References="References",
                            )
                        ],
                        Checks=[],
                    )
                ],
            ),
        }

    def get_custom_check_metadata(self):
        return {
            "check1": CheckMetadata(
                Provider="aws",
                CheckID="check1",
                CheckTitle="Check 1",
                CheckType=["type1"],
                ServiceName="service1",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="url1",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {"Text": "text1", "Url": "url1"},
                },
                Categories=["categoryone"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                Compliance=[],
            ),
            "check2": CheckMetadata(
                Provider="aws",
                CheckID="check2",
                CheckTitle="Check 2",
                CheckType=["type2"],
                ServiceName="service2",
                SubServiceName="subservice2",
                ResourceIdTemplate="template2",
                Severity="medium",
                ResourceType="resource2",
                Description="Description 2",
                Risk="risk2",
                RelatedUrl="url2",
                Remediation={
                    "Code": {
                        "CLI": "cli2",
                        "NativeIaC": "native2",
                        "Other": "other2",
                        "Terraform": "terraform2",
                    },
                    "Recommendation": {"Text": "text2", "Url": "url2"},
                },
                Categories=["categorytwo"],
                DependsOn=["dependency2"],
                RelatedTo=["related2"],
                Notes="notes2",
                Compliance=[],
            ),
        }

    def test_update_checks_metadata(self):
        bulk_compliance_frameworks = self.get_custom_framework()
        bulk_checks_metadata = self.get_custom_check_metadata()

        updated_metadata = update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )

        assert "check1" in updated_metadata
        assert "check2" in updated_metadata

        check1_compliance = updated_metadata["check1"].Compliance[0]

        assert len(updated_metadata["check1"].Compliance) == 1
        assert check1_compliance.Framework == "Framework1"
        assert check1_compliance.Provider == "aws"
        assert check1_compliance.Version == "1.0"
        assert check1_compliance.Description == "Framework 1 Description"
        assert len(check1_compliance.Requirements) == 1

        check1_requirement = check1_compliance.Requirements[0]
        assert check1_requirement.Id == "1.1.1"
        assert check1_requirement.Description == "description"
        assert len(check1_requirement.Attributes) == 1

        check1_attribute = check1_requirement.Attributes[0]
        assert check1_attribute.Section == "1. Identity"
        assert check1_attribute.Profile == "Level 1"
        assert check1_attribute.AssessmentStatus == "Manual"
        assert check1_attribute.Description == "Description"
        assert check1_attribute.RationaleStatement == "Rationale"
        assert check1_attribute.ImpactStatement == "Impact"
        assert check1_attribute.RemediationProcedure == "Remediation"
        assert check1_attribute.AuditProcedure == "Audit"
        assert check1_attribute.AdditionalInformation == "Additional"
        assert check1_attribute.References == "References"

    def test_list_no_provider(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list(bulk_compliance_frameworks)

        assert len(list_compliance) == 2
        assert list_compliance[0] == "framework1_aws"
        assert list_compliance[1] == "framework1_azure"

    def test_list_with_provider_aws(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list(bulk_compliance_frameworks, provider="aws")

        assert len(list_compliance) == 1
        assert list_compliance[0] == "framework1_aws"

    def test_list_with_provider_azure(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list(bulk_compliance_frameworks, provider="azure")

        assert len(list_compliance) == 1
        assert list_compliance[0] == "framework1_azure"

    def test_get_compliance_frameworks(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        compliance_framework = Compliance.get(
            bulk_compliance_frameworks, compliance_framework_name="framework1_aws"
        )

        assert compliance_framework.Framework == "Framework1"
        assert compliance_framework.Provider == "aws"
        assert compliance_framework.Version == "1.0"
        assert compliance_framework.Description == "Framework 1 Description"
        assert len(compliance_framework.Requirements) == 2

        compliance_framework = Compliance.get(
            bulk_compliance_frameworks, compliance_framework_name="framework1_azure"
        )

        assert compliance_framework.Framework == "Framework1"
        assert compliance_framework.Provider == "azure"
        assert compliance_framework.Version == "1.0"
        assert compliance_framework.Description == "Framework 2 Description"
        assert len(compliance_framework.Requirements) == 1

    def test_get_non_existent_framework(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        compliance_framework = Compliance.get(
            bulk_compliance_frameworks, compliance_framework_name="non_existent"
        )

        assert compliance_framework is None

    def test_list_compliance_requirements_no_compliance(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_requirements = Compliance.list_requirements(bulk_compliance_frameworks)

        assert len(list_requirements) == 0

    def test_list_compliance_requirements_with_compliance(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_requirements = Compliance.list_requirements(
            bulk_compliance_frameworks, compliance_framework="framework1_aws"
        )

        assert len(list_requirements) == 2
        assert list_requirements[0] == "1.1.1"
        assert list_requirements[1] == "1.1.2"

        list_requirements = Compliance.list_requirements(
            bulk_compliance_frameworks, compliance_framework="framework1_azure"
        )

        assert len(list_requirements) == 1
        assert list_requirements[0] == "1.1.1"

    def test_get_compliance_requirement(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        compliance_requirement = Compliance.get_requirement(
            bulk_compliance_frameworks,
            compliance_framework="framework1_aws",
            requirement_id="1.1.1",
        )

        assert compliance_requirement.Id == "1.1.1"
        assert compliance_requirement.Description == "description"
        assert len(compliance_requirement.Attributes) == 1

        compliance_requirement = Compliance.get_requirement(
            bulk_compliance_frameworks,
            compliance_framework="framework1_aws",
            requirement_id="1.1.2",
        )

        assert compliance_requirement.Id == "1.1.2"
        assert compliance_requirement.Description == "description"
        assert len(compliance_requirement.Attributes) == 1

        compliance_requirement = Compliance.get_requirement(
            bulk_compliance_frameworks,
            compliance_framework="framework1_azure",
            requirement_id="1.1.1",
        )

        assert compliance_requirement.Id == "1.1.1"
        assert compliance_requirement.Description == "description"
        assert len(compliance_requirement.Attributes) == 1

    def test_get_compliance_requirement_not_found(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        compliance_requirement = Compliance.get_requirement(
            bulk_compliance_frameworks,
            compliance_framework="framework1_aws",
            requirement_id="1.1.3",
        )

        assert compliance_requirement is None

    @mock.patch("prowler.lib.check.compliance_models.load_compliance_framework")
    @mock.patch("os.stat")
    @mock.patch("os.path.isfile")
    @mock.patch("os.listdir")
    @mock.patch("prowler.lib.check.compliance_models.list_compliance_modules")
    def test_get_bulk(
        self,
        mock_list_modules,
        mock_listdir,
        mock_isfile,
        mock_stat,
        mock_load_compliance,
    ):
        object = mock.Mock()
        object.path = "/path/to/compliance"
        object.name = "framework1_aws"
        mock_list_modules.return_value = [object]

        mock_listdir.return_value = ["framework1_aws.json"]

        mock_isfile.return_value = True

        mock_stat.return_value.st_size = 100

        mock_load_compliance.return_value = mock.Mock(
            Framework="Framework1", Provider="aws"
        )

        from prowler.lib.check.compliance_models import Compliance

        result = Compliance.get_bulk(provider="aws")

        assert len(result) == 1
        assert "framework1_aws" in result.keys()
        mock_list_modules.assert_called_once()
