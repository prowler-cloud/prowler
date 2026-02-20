import json
from datetime import datetime
from types import SimpleNamespace
from typing import Optional, Union

from pydantic.v1 import BaseModel, Field, ValidationError

from prowler.config.config import prowler_version
from prowler.lib.check.models import (
    Check_Report,
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.common import Status, fill_common_finding_data
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.utils import unroll_tags
from prowler.lib.utils.utils import dict_to_lowercase, get_nested_attribute
from prowler.providers.common.provider import Provider
from prowler.providers.github.models import GithubAppIdentityInfo, GithubIdentityInfo


class Finding(BaseModel):
    """
    Represents the output model for a finding across different providers.

    This class encapsulates the details of a finding and supports
    serialization to various formats such as CSV. It serves as the base
    model for storing and managing finding information for every provider.
    """

    auth_method: str
    timestamp: Union[int, datetime]
    account_uid: str
    account_name: Optional[str] = None
    account_email: Optional[str] = None
    account_organization_uid: Optional[str] = None
    account_organization_name: Optional[str] = None
    metadata: CheckMetadata
    account_tags: dict = Field(default_factory=dict)
    uid: str
    status: Status
    status_extended: str
    muted: bool = False
    resource_uid: str
    resource_metadata: dict = Field(default_factory=dict)
    resource_name: str
    resource_details: str
    resource_tags: dict = Field(default_factory=dict)
    partition: Optional[str] = None
    region: str
    compliance: dict = Field(default_factory=dict)
    prowler_version: str = prowler_version
    raw: dict = Field(default_factory=dict)

    @property
    def provider(self) -> str:
        """
        Returns the provider from the finding check's metadata.
        """
        return self.metadata.Provider

    @property
    def check_id(self) -> str:
        """
        Returns the ID from the finding check's metadata.
        """
        return self.metadata.CheckID

    @property
    def severity(self) -> str:
        """
        Returns the severity from the finding check's metadata.
        """
        return self.metadata.Severity

    @property
    def resource_type(self) -> str:
        """
        Returns the resource type from the finding check's metadata.
        """
        return self.metadata.ResourceType

    @property
    def service_name(self) -> str:
        """
        Returns the service name from the finding check's metadata.
        """
        return self.metadata.ServiceName

    def get_metadata(self) -> dict:
        """
        Retrieves the metadata of the object and returns it as a dictionary with all keys in lowercase.
        Returns:
            dict: A dictionary containing the metadata with keys converted to lowercase.
        """
        return dict_to_lowercase(self.metadata.dict())

    @classmethod
    def generate_output(
        cls, provider: Provider, check_output: Check_Report, output_options
    ) -> "Finding":
        """Generates the output for a finding based on the provider and output options

        Args:
            provider (Provider): the provider object
            check_output (Check_Report): the check output object
            output_options: the output options object, depending on the provider
        Returns:
            finding_output (Finding): the finding output object

        """
        # TODO: move fill_common_finding_data
        unix_timestamp = False
        if hasattr(output_options, "unix_timestamp"):
            unix_timestamp = output_options.unix_timestamp

        common_finding_data = fill_common_finding_data(check_output, unix_timestamp)
        output_data = {}
        output_data.update(common_finding_data)

        try:
            output_data["compliance"] = check_output.compliance
        except AttributeError:
            bulk_checks_metadata = {}
            if hasattr(output_options, "bulk_checks_metadata"):
                bulk_checks_metadata = output_options.bulk_checks_metadata

            output_data["compliance"] = get_check_compliance(
                check_output, provider.type, bulk_checks_metadata
            )
        try:
            output_data["provider"] = provider.type
            output_data["resource_metadata"] = check_output.resource

            if provider.type == "aws":
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.account"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "organizations_metadata.account_name"
                )
                output_data["account_email"] = get_nested_attribute(
                    provider, "organizations_metadata.account_email"
                )
                output_data["account_organization_uid"] = get_nested_attribute(
                    provider, "organizations_metadata.organization_arn"
                )
                output_data["account_organization_name"] = get_nested_attribute(
                    provider, "organizations_metadata.organization_id"
                )
                output_data["account_tags"] = get_nested_attribute(
                    provider, "organizations_metadata.account_tags"
                )
                output_data["partition"] = get_nested_attribute(
                    provider, "identity.partition"
                )

                # TODO: probably Organization UID is without the account id
                output_data["auth_method"] = (
                    f"profile: {get_nested_attribute(provider, 'identity.profile')}"
                )
                output_data["resource_name"] = check_output.resource_id
                output_data["resource_uid"] = check_output.resource_arn
                output_data["region"] = check_output.region

            elif provider.type == "azure":
                # TODO: we should show the authentication method used I think
                output_data["auth_method"] = (
                    f"{provider.identity.identity_type}: {provider.identity.identity_id}"
                )
                # Get the first tenant domain ID, just in case
                output_data["account_organization_uid"] = get_nested_attribute(
                    provider, "identity.tenant_ids"
                )[0]
                output_data["account_uid"] = (
                    output_data["account_organization_uid"]
                    if "Tenant:" in check_output.subscription
                    else provider.identity.subscriptions[check_output.subscription]
                )
                output_data["account_name"] = check_output.subscription
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location
                # TODO: check the tenant_ids
                # TODO: we have to get the account organization, the tenant is not that
                output_data["account_organization_name"] = get_nested_attribute(
                    provider, "identity.tenant_domain"
                )

                output_data["partition"] = get_nested_attribute(
                    provider, "region_config.name"
                )
                # TODO: pending to get the subscription tags
                # "account_tags": "organizations_metadata.account_details_tags",
                # TODO: store subscription_name + id pairs
                # "account_name": "organizations_metadata.account_details_name",
                # "account_email": "organizations_metadata.account_details_email",

            elif provider.type == "gcp":
                output_data["auth_method"] = (
                    f"Principal: {get_nested_attribute(provider, 'identity.profile')}"
                )
                output_data["account_uid"] = provider.projects[
                    check_output.project_id
                ].id
                output_data["account_name"] = provider.projects[
                    check_output.project_id
                ].name
                # There is no concept as project email in GCP
                # "account_email": "organizations_metadata.account_details_email",
                output_data["account_tags"] = provider.projects[
                    check_output.project_id
                ].labels
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location

                if (
                    provider.projects
                    and check_output.project_id in provider.projects
                    and getattr(
                        provider.projects[check_output.project_id], "organization"
                    )
                ):
                    output_data["account_organization_uid"] = provider.projects[
                        check_output.project_id
                    ].organization.id
                    # TODO: for now is None since we don't retrieve that data
                    output_data["account_organization_name"] = provider.projects[
                        check_output.project_id
                    ].organization.display_name

            elif provider.type == "kubernetes":
                if provider.identity.context == "In-Cluster":
                    output_data["auth_method"] = "in-cluster"
                else:
                    output_data["auth_method"] = "kubeconfig"
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["account_name"] = f"context: {provider.identity.context}"
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.cluster"
                )
                output_data["region"] = f"namespace: {check_output.namespace}"

            elif provider.type == "github":
                output_data["auth_method"] = provider.auth_method
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id

                if isinstance(provider.identity, GithubIdentityInfo):
                    # GithubIdentityInfo (Personal Access Token, OAuth)
                    output_data["account_name"] = provider.identity.account_name
                    output_data["account_uid"] = provider.identity.account_id
                    output_data["account_email"] = provider.identity.account_email
                elif isinstance(provider.identity, GithubAppIdentityInfo):
                    # GithubAppIdentityInfo (GitHub App)
                    output_data["account_name"] = provider.identity.app_name
                    output_data["account_uid"] = provider.identity.app_id
                    output_data["installations"] = provider.identity.installations

                output_data["region"] = check_output.owner

            elif provider.type == "m365":
                output_data["auth_method"] = (
                    f"{provider.identity.identity_type}: {provider.identity.identity_id}"
                )
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.tenant_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.tenant_domain"
                )
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location

            elif provider.type == "mongodbatlas":
                output_data["auth_method"] = "api_key"
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.organization_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.organization_name"
                )
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location

            elif provider.type == "nhn":
                output_data["auth_method"] = (
                    f"passwordCredentials: username={get_nested_attribute(provider, '_identity.username')}, "
                    f"tenantId={get_nested_attribute(provider, '_identity.tenant_id')}"
                )
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.tenant_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.tenant_domain"
                )
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location

            elif provider.type == "iac":
                output_data["auth_method"] = provider.auth_method
                output_data["account_uid"] = "iac"
                output_data["account_name"] = "iac"
                output_data["resource_name"] = getattr(
                    check_output, "resource_name", ""
                )
                output_data["resource_uid"] = getattr(check_output, "resource_name", "")
                # For IaC, resource_line_range only exists on CheckReportIAC, not on Finding objects
                output_data["region"] = getattr(check_output, "region", "global")
                output_data["resource_line_range"] = getattr(
                    check_output, "resource_line_range", ""
                )
                output_data["framework"] = check_output.check_metadata.ServiceName

            elif provider.type == "llm":
                output_data["auth_method"] = provider.auth_method
                output_data["account_uid"] = "llm"
                output_data["account_name"] = "llm"
                output_data["resource_name"] = check_output.model
                output_data["resource_uid"] = check_output.model
                output_data["region"] = check_output.model

            elif provider.type == "oraclecloud":
                output_data["auth_method"] = (
                    f"Profile: {get_nested_attribute(provider, 'session.profile')}"
                )
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.tenancy_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.tenancy_name"
                )
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.region

            elif provider.type == "cloudflare":
                output_data["auth_method"] = "api_token"
                output_data["account_uid"] = check_output.account_id
                output_data["account_name"] = check_output.account_id
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.zone_name

            elif provider.type == "alibabacloud":
                output_data["auth_method"] = get_nested_attribute(
                    provider, "identity.identity_arn"
                )
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.account_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.account_name"
                )
                output_data["resource_name"] = check_output.resource_id
                output_data["resource_uid"] = getattr(
                    check_output, "resource_arn", check_output.resource_id
                )
                output_data["region"] = check_output.region

            elif provider.type == "openstack":
                output_data["auth_method"] = (
                    f"Username: {get_nested_attribute(provider, 'identity.username')}"
                )
                output_data["account_uid"] = get_nested_attribute(
                    provider, "identity.project_id"
                )
                output_data["account_name"] = get_nested_attribute(
                    provider, "identity.project_name"
                )
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.region

            elif provider.type == "image":
                output_data["auth_method"] = provider.auth_method
                output_data["account_uid"] = "image"
                output_data["account_name"] = "image"
                image_name = getattr(check_output, "resource_name", "")
                image_sha = getattr(check_output, "image_sha", "")
                output_data["resource_name"] = image_name
                output_data["resource_uid"] = (
                    f"{image_name}:{image_sha}" if image_sha else image_name
                )
                output_data["region"] = getattr(check_output, "region", "container")
                output_data["package_name"] = getattr(check_output, "package_name", "")
                output_data["installed_version"] = getattr(
                    check_output, "installed_version", ""
                )
                output_data["fixed_version"] = getattr(
                    check_output, "fixed_version", ""
                )

            # check_output Unique ID
            # TODO: move this to a function
            # TODO: in Azure, GCP and K8s there are findings without resource_name
            output_data["uid"] = (
                f"prowler-{provider.type}-{check_output.check_metadata.CheckID}-{output_data['account_uid']}-"
                f"{output_data['region']}-{output_data['resource_name']}"
            )

            if not output_data["resource_uid"]:
                logger.error(
                    f"Check {check_output.check_metadata.CheckID} has no resource_uid."
                )
            if not output_data["resource_name"]:
                logger.error(
                    f"Check {check_output.check_metadata.CheckID} has no resource_name."
                )

            return cls(**output_data)
        except ValidationError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error} - {output_data}"
            )
            raise validation_error
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    @classmethod
    def transform_api_finding(cls, finding, provider) -> "Finding":
        """
        Transform a FindingModel instance into an API-friendly Finding object.

        This class method extracts data from a FindingModel instance and maps its
        properties to a new Finding object. The transformation populates various
        fields including authentication details, timestamp, account information,
        check metadata (such as provider, check ID, title, type, service, severity,
        and remediation details), as well as resource-specific data. The resulting
        Finding object is structured for use in API responses or further processing.

        Args:
            finding (API Finding): An API Finding instance containing data from the database.
            provider (Provider): the provider object.

        Returns:
            Finding: A new Finding instance populated with data from the provided model.
        """
        # Missing Finding's API values
        resource = finding.resources.first()
        finding.resource_arn = resource.uid
        finding.resource_name = resource.name
        finding.resource = json.loads(resource.metadata)
        finding.resource_details = resource.details

        finding.resource_id = resource.name if provider.type == "aws" else resource.uid

        # AWS specified field
        finding.region = resource.region
        # Azure, GCP specified field
        finding.location = resource.region
        # GitHub specified field
        finding.owner = resource.region
        # K8s specified field
        if provider.type == "kubernetes":
            finding.namespace = resource.region.removeprefix("namespace: ")
        if provider.type == "azure":
            finding.subscription = list(provider.identity.subscriptions.keys())[0]
        elif provider.type == "gcp":
            finding.project_id = list(provider.projects.keys())[0]
        elif provider.type == "iac":
            # For IaC, we don't have resource_line_range in the Finding model
            # It would need to be extracted from the resource metadata if needed
            finding.resource_line_range = ""  # Set empty for compatibility
        elif provider.type == "oraclecloud":
            finding.compartment_id = getattr(finding, "compartment_id", "")
        elif provider.type == "cloudflare":
            finding.zone_name = getattr(resource, "zone_name", resource.name)
            finding.account_id = getattr(finding, "account_id", "")

        finding.check_metadata = CheckMetadata(
            Provider=finding.check_metadata["provider"],
            CheckID=finding.check_metadata["checkid"],
            CheckTitle=finding.check_metadata["checktitle"],
            CheckType=finding.check_metadata["checktype"],
            ServiceName=finding.check_metadata["servicename"],
            SubServiceName=finding.check_metadata["subservicename"],
            Severity=finding.check_metadata["severity"],
            ResourceType=finding.check_metadata["resourcetype"],
            Description=finding.check_metadata["description"],
            Risk=finding.check_metadata["risk"],
            RelatedUrl=finding.check_metadata["relatedurl"],
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.check_metadata["remediation"]["recommendation"][
                        "text"
                    ],
                    Url=finding.check_metadata["remediation"]["recommendation"]["url"],
                ),
                Code=Code(
                    NativeIaC=finding.check_metadata["remediation"]["code"][
                        "nativeiac"
                    ],
                    Terraform=finding.check_metadata["remediation"]["code"][
                        "terraform"
                    ],
                    CLI=finding.check_metadata["remediation"]["code"]["cli"],
                    Other=finding.check_metadata["remediation"]["code"]["other"],
                ),
            ),
            ResourceIdTemplate=finding.check_metadata["resourceidtemplate"],
            Categories=finding.check_metadata["categories"],
            DependsOn=finding.check_metadata["dependson"],
            RelatedTo=finding.check_metadata["relatedto"],
            Notes=finding.check_metadata["notes"],
        )
        finding.resource_tags = unroll_tags(
            [{"key": tag.key, "value": tag.value} for tag in resource.tags.all()]
        )

        return cls.generate_output(provider, finding, SimpleNamespace())

    def _transform_findings_stats(scan_summaries: list[dict]) -> dict:
        """
        Aggregate and transform scan summary data into findings statistics.

        This function processes a list of scan summary objects and calculates overall
        metrics such as the total number of passed and failed findings (including muted counts),
        as well as a breakdown of results by severity (critical, high, medium, and low).
        It also retrieves the unique resource count from the associated scan information.
        The final output is a dictionary of aggregated statistics intended for reporting or
        further analysis.

        Args:
            scan_summaries (list[dict]): A list of scan summary objects. Each object is expected
                                        to have attributes including:
                                        - _pass: Number of passed findings.
                                        - fail: Number of failed findings.
                                        - total: Total number of findings.
                                        - muted: Number indicating if the finding is muted.
                                        - severity: A string representing the severity level.
                                        Additionally, the first scan summary should have an associated
                                        `scan` attribute with a `unique_resource_count`.

        Returns:
            dict: A dictionary containing aggregated findings statistics:
                - total_pass: Total number of passed findings.
                - total_muted_pass: Total number of muted passed findings.
                - total_fail: Total number of failed findings.
                - total_muted_fail: Total number of muted failed findings.
                - resources_count: The unique resource count extracted from the scan.
                - findings_count: Total number of findings.
                - total_critical_severity_fail: Failed findings with critical severity.
                - total_critical_severity_pass: Passed findings with critical severity.
                - total_high_severity_fail: Failed findings with high severity.
                - total_high_severity_pass: Passed findings with high severity.
                - total_medium_severity_fail: Failed findings with medium severity.
                - total_medium_severity_pass: Passed findings with medium severity.
                - total_low_severity_fail: Failed findings with low severity.
                - total_low_severity_pass: Passed findings with low severity.
                - all_fails_are_muted: A boolean indicating whether all failing findings are muted.
        """
        # Initialize overall counters
        total_pass = 0
        total_fail = 0
        muted_pass = 0
        muted_fail = 0
        findings_count = 0
        resources_count = scan_summaries[0].scan.unique_resource_count

        # Initialize severity breakdown counters
        critical_severity_pass = 0
        critical_severity_fail = 0
        high_severity_pass = 0
        high_severity_fail = 0
        medium_severity_pass = 0
        medium_severity_fail = 0
        low_severity_pass = 0
        low_severity_fail = 0

        # Loop over each row from the database
        for row in scan_summaries:
            # Accumulate overall totals
            total_pass += row._pass
            total_fail += row.fail
            findings_count += row.total

            if row.muted > 0:
                if row._pass > 0:
                    muted_pass += row._pass
                if row.fail > 0:
                    muted_fail += row.fail

            sev = row.severity.lower()
            if sev == "critical":
                critical_severity_pass += row._pass
                critical_severity_fail += row.fail
            elif sev == "high":
                high_severity_pass += row._pass
                high_severity_fail += row.fail
            elif sev == "medium":
                medium_severity_pass += row._pass
                medium_severity_fail += row.fail
            elif sev == "low":
                low_severity_pass += row._pass
                low_severity_fail += row.fail

        all_fails_are_muted = (total_fail > 0) and (total_fail == muted_fail)

        stats = {
            "total_pass": total_pass,
            "total_muted_pass": muted_pass,
            "total_fail": total_fail,
            "total_muted_fail": muted_fail,
            "resources_count": resources_count,
            "findings_count": findings_count,
            "total_critical_severity_fail": critical_severity_fail,
            "total_critical_severity_pass": critical_severity_pass,
            "total_high_severity_fail": high_severity_fail,
            "total_high_severity_pass": high_severity_pass,
            "total_medium_severity_fail": medium_severity_fail,
            "total_medium_severity_pass": medium_severity_pass,
            "total_low_severity_fail": low_severity_fail,
            "total_low_severity_pass": low_severity_pass,
            "all_fails_are_muted": all_fails_are_muted,
        }
        return stats
