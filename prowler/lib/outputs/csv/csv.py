from csv import DictWriter
from operator import attrgetter
from typing import Any

from prowler.lib.logger import logger
from prowler.lib.outputs.csv.models import CSVRow


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


def generate_provider_output_csv(provider, finding, csv_data) -> CSVRow:
    """
    generate_provider_output_csv creates the provider's CSV output
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

        elif provider.type == "k8s":
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

        finding_output = CSVRow(**csv_data)

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    else:
        return finding_output


def write_csv(file_descriptor, headers, row):
    csv_writer = DictWriter(
        file_descriptor,
        fieldnames=headers,
        delimiter=";",
    )
    csv_writer.writerow(row.__dict__)


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    # __fields__ is always available in the Pydantic's BaseModel class
    for field in format.__dict__.get("__fields__").keys():
        csv_fields.append(field)
    return csv_fields
