from datetime import datetime
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field

from prowler.config.config import prowler_version
from prowler.lib.check.models import Check_Report, CheckMetadata
from prowler.lib.logger import logger
from prowler.lib.outputs.common import (
    fill_common_finding_data,
    get_provider_data_mapping,
)
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.utils.utils import dict_to_lowercase
from prowler.providers.common.provider import Provider


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


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
    account_tags: dict = {}
    uid: str
    status: Status
    status_extended: str
    muted: bool = False
    resource_uid: str
    resource_name: str
    resource_details: str
    resource_tags: dict = Field(default_factory=dict)
    partition: Optional[str] = None
    region: str
    compliance: dict
    prowler_version: str = prowler_version

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

    @property
    def raw(self) -> dict:
        """
        Returns the raw (dict) finding without any post-processing.
        """
        return {}

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
        # TODO: think about get_provider_data_mapping
        provider_data_mapping = get_provider_data_mapping(provider)

        # TODO: move fill_common_finding_data
        unix_timestamp = False
        if hasattr(output_options, "unix_timestamp"):
            unix_timestamp = output_options.unix_timestamp

        common_finding_data = fill_common_finding_data(check_output, unix_timestamp)
        output_data = {}
        output_data.update(provider_data_mapping)
        output_data.update(common_finding_data)

        bulk_checks_metadata = {}
        if hasattr(output_options, "bulk_checks_metadata"):
            bulk_checks_metadata = output_options.bulk_checks_metadata

        output_data["compliance"] = get_check_compliance(
            check_output, provider.type, bulk_checks_metadata
        )
        try:
            if provider.type == "aws":
                # TODO: probably Organization UID is without the account id
                output_data["auth_method"] = f"profile: {output_data['auth_method']}"
                output_data["resource_name"] = check_output.resource_id
                output_data["resource_uid"] = check_output.resource_arn
                output_data["region"] = check_output.region

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
                    if "Tenant:" in check_output.subscription
                    else provider.identity.subscriptions[check_output.subscription]
                )
                output_data["account_name"] = check_output.subscription
                output_data["resource_name"] = check_output.resource_name
                output_data["resource_uid"] = check_output.resource_id
                output_data["region"] = check_output.location

            elif provider.type == "gcp":
                output_data["auth_method"] = f"Principal: {output_data['auth_method']}"
                output_data["account_uid"] = provider.projects[
                    check_output.project_id
                ].id
                output_data["account_name"] = provider.projects[
                    check_output.project_id
                ].name
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
                output_data["region"] = f"namespace: {check_output.namespace}"

            # check_output Unique ID
            # TODO: move this to a function
            # TODO: in Azure, GCP and K8s there are fidings without resource_name
            output_data["uid"] = (
                f"prowler-{provider.type}-{check_output.check_metadata.CheckID}-{output_data['account_uid']}-"
                f"{output_data['region']}-{output_data['resource_name']}"
            )

            return cls(**output_data)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
