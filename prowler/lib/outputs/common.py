from operator import attrgetter

from prowler.config.config import timestamp
from prowler.lib.logger import logger
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.utils import unroll_list, unroll_tags
from prowler.lib.utils.utils import outputs_unix_timestamp


def get_provider_data_mapping(provider) -> dict:
    data = {}
    for generic_field, provider_field in provider.get_output_mapping.items():
        try:
            provider_value = attrgetter(provider_field)(provider)
            data[generic_field] = provider_value
        except AttributeError as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            data[generic_field] = None

    return data


def generate_provider_output(provider, finding, csv_data) -> FindingOutput:
    """
    generate_provider_output returns the provider's Finding output model
    """
    # TODO: we have to standardize this between the above mapping and the provider.get_output_mapping()
    try:
        if provider.type == "aws":
            # TODO: probably Organization UID is without the account id
            csv_data["auth_method"] = f"profile: {csv_data['auth_method']}"
            csv_data["resource_name"] = finding.resource_id
            csv_data["resource_uid"] = finding.resource_arn
            csv_data["region"] = finding.region

        elif provider.type == "azure":
            # TODO: we should show the authentication method used I think
            csv_data["auth_method"] = (
                f"{provider.identity.identity_type}: {provider.identity.identity_id}"
            )

            csv_data["account_uid"] = provider.identity.subscriptions[
                finding.subscription
            ]
            csv_data["account_name"] = finding.subscription
            # Get the first tenant domain ID, just in case
            csv_data["account_organization_uid"] = csv_data["account_organization_uid"][
                0
            ]
            csv_data["resource_name"] = finding.resource_name
            csv_data["resource_uid"] = finding.resource_id
            # TODO: pending to get location from Azure resources (finding.location)
            csv_data["region"] = ""

        elif provider.type == "gcp":
            csv_data["auth_method"] = f"Principal: {csv_data['auth_method']}"
            csv_data["account_uid"] = provider.projects[finding.project_id].number
            csv_data["account_name"] = provider.projects[finding.project_id].name
            csv_data["account_tags"] = provider.projects[finding.project_id].labels
            csv_data["resource_name"] = finding.resource_name
            csv_data["resource_uid"] = finding.resource_id
            csv_data["region"] = finding.location

            if (
                provider.projects
                and finding.project_id in provider.projects
                and getattr(provider.projects[finding.project_id], "organization")
            ):
                csv_data["account_organization_uid"] = provider.projects[
                    finding.project_id
                ].organization.id
                # TODO: for now is None since we don't retrieve that data
                csv_data["account_organization"] = provider.projects[
                    finding.project_id
                ].organization.display_name

        elif provider.type == "kubernetes":
            if provider.identity.context == "In-Cluster":
                csv_data["auth_method"] = "in-cluster"
            else:
                csv_data["auth_method"] = "kubeconfig"
            csv_data["resource_name"] = finding.resource_name
            csv_data["resource_uid"] = finding.resource_id
            csv_data["account_name"] = f"context: {provider.identity.context}"
            csv_data["region"] = f"namespace: {finding.namespace}"

        # Finding Unique ID
        # TODO: move this to a function
        # TODO: in Azure, GCP and K8s there are fidings without resource_name
        csv_data["finding_uid"] = (
            f"prowler-{provider.type}-{finding.check_metadata.CheckID}-{csv_data['account_uid']}-{csv_data['region']}-{csv_data['resource_name']}"
        )

        finding_output = FindingOutput(**csv_data)

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    else:
        return finding_output


def fill_common_finding_data(finding: dict, unix_timestamp: bool) -> dict:
    finding_data = {
        "timestamp": outputs_unix_timestamp(unix_timestamp, timestamp),
        "check_id": finding.check_metadata.CheckID,
        "check_title": finding.check_metadata.CheckTitle,
        "check_type": ",".join(finding.check_metadata.CheckType),
        "status": finding.status,
        "status_extended": finding.status_extended,
        "muted": finding.muted,
        "service_name": finding.check_metadata.ServiceName,
        "subservice_name": finding.check_metadata.SubServiceName,
        "severity": finding.check_metadata.Severity,
        "resource_type": finding.check_metadata.ResourceType,
        "resource_details": finding.resource_details,
        "resource_tags": unroll_tags(finding.resource_tags),
        "description": finding.check_metadata.Description,
        "risk": finding.check_metadata.Risk,
        "related_url": finding.check_metadata.RelatedUrl,
        "remediation_recommendation_text": (
            finding.check_metadata.Remediation.Recommendation.Text
        ),
        "remediation_recommendation_url": (
            finding.check_metadata.Remediation.Recommendation.Url
        ),
        "remediation_code_nativeiac": (
            finding.check_metadata.Remediation.Code.NativeIaC
        ),
        "remediation_code_terraform": (
            finding.check_metadata.Remediation.Code.Terraform
        ),
        "remediation_code_cli": (finding.check_metadata.Remediation.Code.CLI),
        "remediation_code_other": (finding.check_metadata.Remediation.Code.Other),
        "categories": unroll_list(finding.check_metadata.Categories),
        "depends_on": unroll_list(finding.check_metadata.DependsOn),
        "related_to": unroll_list(finding.check_metadata.RelatedTo),
        "notes": finding.check_metadata.Notes,
    }
    return finding_data
