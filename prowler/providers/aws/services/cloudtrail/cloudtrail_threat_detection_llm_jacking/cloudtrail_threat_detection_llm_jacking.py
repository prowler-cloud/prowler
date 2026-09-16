from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    get_cloudtrail_account_resource,
    get_cloudtrail_threat_detection_identities,
)

default_threat_detection_llm_jacking_actions = [
    "PutUseCaseForModelAccess",
    "PutFoundationModelEntitlement",
    "PutModelInvocationLoggingConfiguration",
    "CreateFoundationModelAgreement",
    "InvokeModel",
    "InvokeModelWithResponseStream",
    "GetUseCaseForModelAccess",
    "GetModelInvocationLoggingConfiguration",
    "GetFoundationModelAvailability",
    "ListFoundationModelAgreementOffers",
    "ListFoundationModels",
    "ListProvisionedModelThroughputs",
    "SearchAgreements",
    "AcceptAgreementRequest",
]


class cloudtrail_threat_detection_llm_jacking(Check):
    """Detect potential LLM jacking activity recorded by CloudTrail."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate CloudTrail events for potential LLM jacking activity.

        Returns:
            list[Check_Report_AWS]: Reports for detected identities or the account.
        """
        findings = []
        threshold = cloudtrail_client.audit_config.get(
            "threat_detection_llm_jacking_threshold", 0.4
        )
        threat_detection_minutes = cloudtrail_client.audit_config.get(
            "threat_detection_llm_jacking_minutes", 1440
        )
        llm_jacking_actions = cloudtrail_client.audit_config.get(
            "threat_detection_llm_jacking_actions",
            default_threat_detection_llm_jacking_actions,
        )
        found_potential_llm_jacking = False
        potential_llm_jacking = get_cloudtrail_threat_detection_identities(
            cloudtrail_client, llm_jacking_actions, threat_detection_minutes
        )

        if potential_llm_jacking is None:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate CloudTrail threat detection because CloudTrail trails or events could not be retrieved in at least one audited region. Verify that the scanning credentials are allowed to call cloudtrail:DescribeTrails and cloudtrail:LookupEvents."
            return [report]

        for resource, actions in potential_llm_jacking.values():
            identity_threshold = round(len(actions) / len(llm_jacking_actions), 2)
            if len(actions) / len(llm_jacking_actions) > threshold:
                found_potential_llm_jacking = True
                report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
                report.status = "FAIL"
                report.status_extended = f"Potential LLM Jacking attack detected from AWS {resource.identity_type} {resource.name} with a threshold of {identity_threshold}."
                findings.append(report)
        if not found_potential_llm_jacking:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "PASS"
            report.status_extended = "No potential LLM Jacking attack detected."
            findings.append(report)
        return findings
