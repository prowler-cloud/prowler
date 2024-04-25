from datetime import datetime

from prowler.config.config import prowler_version
from prowler.lib.outputs.common_models import FindingOutput
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER


# TODO: customize it per provider
def generate_finding_output(status, severity, muted, region) -> FindingOutput:
    # TODO: Include metadata from a valid file

    return FindingOutput(
        auth_method="profile: default",
        timestamp=datetime.now(),
        account_uid=AWS_ACCOUNT_NUMBER,
        account_name=AWS_ACCOUNT_NUMBER,
        account_email="",
        account_organization_uid="test-organization-id",
        account_organization_name="test-organization",
        account_tags=["test-tag:test-value"],
        finding_uid="test-unique-finding",
        provider="aws",
        check_id="test-check-id",
        check_title="test-check-id",
        check_type="test-type",
        status=status,
        status_extended="status extended",
        muted=muted,
        service_name="test-service",
        subservice_name="",
        severity=severity,
        resource_type="test-resource",
        resource_uid="resource-id",
        resource_name="resource_name",
        resource_details="resource_details",
        resource_tags="",
        partition="aws",
        region=region,
        description="check description",
        risk="test-risk",
        related_url="test-url",
        remediation_recommendation_text="",
        remediation_recommendation_url="",
        remediation_code_nativeiac="",
        remediation_code_terraform="",
        remediation_code_cli="",
        remediation_code_other="",
        compliance={"test-compliance": "test-compliance"},
        categories="test-category",
        depends_on="test-dependency",
        related_to="test-related-to",
        notes="test-notes",
        prowler_version=prowler_version,
    )
