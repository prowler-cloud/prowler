from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    CIS_Requirement_Attribute_AssessmentStatus,
    CIS_Requirement_Attribute_Profile,
    Compliance_Requirement,
    ComplianceBaseModel,
)
from prowler.lib.check.models import Check_Metadata_Model


class TestCompliance:
    provider = "aws"

    def get_custom_framework(self):
        return {
            "framework1": ComplianceBaseModel(
                Framework="Framework1",
                Provider="Provider1",
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
            )
        }

    def get_custom_check_metadata(self):
        return {
            "check1": Check_Metadata_Model(
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
            "check2": Check_Metadata_Model(
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
        assert check1_compliance.Provider == "Provider1"
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
