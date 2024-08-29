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
            "framework1": Compliance(
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
            "framework2": Compliance(
                Framework="Framework2",
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

    def test_list_compliance_frameworks_no_provider(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list_compliance_frameworks(
            bulk_compliance_frameworks
        )

        assert len(list_compliance) == 2
        assert list_compliance[0].Framework == "Framework1"
        assert list_compliance[0].Provider == "aws"
        assert list_compliance[0].Version == "1.0"
        assert list_compliance[0].Description == "Framework 1 Description"
        assert len(list_compliance[0].Requirements) == 2
        assert list_compliance[1].Framework == "Framework2"
        assert list_compliance[1].Provider == "azure"
        assert list_compliance[1].Version == "1.0"
        assert list_compliance[1].Description == "Framework 2 Description"
        assert len(list_compliance[1].Requirements) == 1

    def test_list_compliance_frameworks_with_provider_aws(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list_compliance_frameworks(
            bulk_compliance_frameworks, provider="aws"
        )

        assert len(list_compliance) == 1
        assert list_compliance[0].Framework == "Framework1"
        assert list_compliance[0].Provider == "aws"
        assert list_compliance[0].Version == "1.0"
        assert list_compliance[0].Description == "Framework 1 Description"
        assert len(list_compliance[0].Requirements) == 2

    def test_list_compliance_frameworks_with_provider_azure(self):
        bulk_compliance_frameworks = self.get_custom_framework()

        list_compliance = Compliance.list_compliance_frameworks(
            bulk_compliance_frameworks, provider="azure"
        )

        assert len(list_compliance) == 1
        assert list_compliance[0].Framework == "Framework2"
        assert list_compliance[0].Provider == "azure"
        assert list_compliance[0].Version == "1.0"
        assert list_compliance[0].Description == "Framework 2 Description"
        assert len(list_compliance[0].Requirements) == 1
