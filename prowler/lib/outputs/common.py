from operator import attrgetter

from prowler.config.config import timestamp
from prowler.lib.logger import logger
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.utils import unroll_list, unroll_tags
from prowler.lib.utils.utils import outputs_unix_timestamp


def get_provider_data_mapping(provider) -> dict:
    data = {}
    for generic_field, provider_field in provider.get_output_mapping.items():
        try:
            provider_value = attrgetter(provider_field)(provider)
            data[generic_field] = provider_value
        except AttributeError:
            data[generic_field] = ""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    return data


def generate_output(provider, finding, output_options) -> FindingOutput:
    provider_data_mapping = get_provider_data_mapping(provider)
    common_finding_data = fill_common_finding_data(
        finding, output_options.unix_timestamp
    )
    output_data = {}
    output_data.update(provider_data_mapping)
    output_data.update(common_finding_data)
    output_data["compliance"] = get_check_compliance(
        finding, provider.type, output_options
    )
    finding_output = generate_provider_output(provider, finding, output_data)
    return finding_output


def generate_provider_output(provider, finding, output_data) -> FindingOutput:
    """
    generate_provider_output returns the provider's Finding output model
    """
    # TODO: we have to standardize this between the above mapping and the provider.get_output_mapping()
    try:
        if provider.type == "aws":
            # TODO: probably Organization UID is without the account id
            output_data["auth_method"] = f"profile: {output_data['auth_method']}"
            output_data["resource_name"] = finding.resource_id
            output_data["resource_uid"] = finding.resource_arn
            output_data["region"] = finding.region

        elif provider.type == "azure":
            # TODO: we should show the authentication method used I think
            output_data["auth_method"] = (
                f"{provider.identity.identity_type}: {provider.identity.identity_id}"
            )
            # Get the first tenant domain ID, just in case
            output_data["account_organization_uid"] = output_data[
                "account_organization_uid"
            ][0]
            output_data["account_uid"] = (
                output_data["account_organization_uid"]
                if "Tenant:" in finding.subscription
                else provider.identity.subscriptions[finding.subscription]
            )
            output_data["account_name"] = finding.subscription
            output_data["resource_name"] = finding.resource_name
            output_data["resource_uid"] = finding.resource_id
            output_data["region"] = finding.location

        elif provider.type == "gcp":
            output_data["auth_method"] = f"Principal: {output_data['auth_method']}"
            output_data["account_uid"] = provider.projects[finding.project_id].id
            output_data["account_name"] = provider.projects[finding.project_id].name
            output_data["account_tags"] = provider.projects[finding.project_id].labels
            output_data["resource_name"] = finding.resource_name
            output_data["resource_uid"] = finding.resource_id
            output_data["region"] = finding.location

            if (
                provider.projects
                and finding.project_id in provider.projects
                and getattr(provider.projects[finding.project_id], "organization")
            ):
                output_data["account_organization_uid"] = provider.projects[
                    finding.project_id
                ].organization.id
                # TODO: for now is None since we don't retrieve that data
                output_data["account_organization"] = provider.projects[
                    finding.project_id
                ].organization.display_name

        elif provider.type == "kubernetes":
            if provider.identity.context == "In-Cluster":
                output_data["auth_method"] = "in-cluster"
            else:
                output_data["auth_method"] = "kubeconfig"
            output_data["resource_name"] = finding.resource_name
            output_data["resource_uid"] = finding.resource_id
            output_data["account_name"] = f"context: {provider.identity.context}"
            output_data["region"] = f"namespace: {finding.namespace}"

        # Finding Unique ID
        # TODO: move this to a function
        # TODO: in Azure, GCP and K8s there are fidings without resource_name
        output_data["finding_uid"] = (
            f"prowler-{provider.type}-{finding.check_metadata.CheckID}-{output_data['account_uid']}-{output_data['region']}-{output_data['resource_name']}"
        )

        finding_output = FindingOutput(**output_data)

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    else:
        return finding_output


# TODO: add test for outputs_unix_timestamp
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
