import copy
from abc import ABC, abstractmethod
from csv import DictWriter
from datetime import datetime
from enum import Enum
from io import TextIOWrapper
from typing import Optional, Union

from pydantic import BaseModel

from prowler.config.config import prowler_version
from prowler.lib.logger import logger
from prowler.lib.outputs.common import (
    fill_common_finding_data,
    get_provider_data_mapping,
)
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.utils import unroll_dict, unroll_list


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Finding(BaseModel):
    """
    Finding generates a finding's output. It can be written to CSV or another format doing the mapping.

    This is the base finding output model for every provider.
    """

    auth_method: str
    timestamp: Union[int, datetime]
    account_uid: str
    # Optional since depends on permissions
    account_name: Optional[str]
    # Optional since depends on permissions
    account_email: Optional[str]
    # Optional since depends on permissions
    account_organization_uid: Optional[str]
    # Optional since depends on permissions
    account_organization_name: Optional[str]
    # Optional since depends on permissions
    account_tags: Optional[list[str]]
    finding_uid: str
    provider: str
    check_id: str
    check_title: str
    check_type: str
    status: Status
    status_extended: str
    muted: bool = False
    service_name: str
    subservice_name: str
    severity: Severity
    resource_type: str
    resource_uid: str
    resource_name: str
    resource_details: str
    resource_tags: str
    # Only present for AWS and Azure
    partition: Optional[str]
    region: str
    description: str
    risk: str
    related_url: str
    remediation_recommendation_text: str
    remediation_recommendation_url: str
    remediation_code_nativeiac: str
    remediation_code_terraform: str
    remediation_code_cli: str
    remediation_code_other: str
    compliance: dict
    categories: str
    depends_on: str
    related_to: str
    notes: str
    prowler_version: str = prowler_version

    @classmethod
    def generate_output(cls, provider, finding, output_options) -> "Finding":
        """generates the output for a finding based on the provider and output options

        Args:
            provider (Provider): the provider object
            finding (Finding): the finding object
            output_options (OutputOptions): the output options object

        Returns:
            finding_output (Finding): the finding output object

        """
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
        finding_output = cls.generate_provider_output(provider, finding, output_data)
        return finding_output

    @classmethod
    def generate_provider_output(cls, provider, finding, output_data) -> "Finding":
        """generates the provider specific output for a finding

        Args:
            provider (Provider): the provider object
            finding (Finding): the finding object
            output_data (dict): the output data

        Returns:
            finding_output (Finding): the finding output object

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
                output_data["account_tags"] = provider.projects[
                    finding.project_id
                ].labels
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

            finding_output = cls(**output_data)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        else:
            return finding_output


class Output(ABC):
    _data: list[object] = []

    def __init__(self, finding: Finding) -> None:
        self.transform(finding)

    @property
    def data(self):
        return self._data

    @abstractmethod
    def transform(self, finding: Finding):
        raise NotImplementedError

    def write_to_file(self, file_descriptor: TextIOWrapper) -> None:
        raise NotImplementedError


class CSV(Output):
    def transform(self, findings: list[Finding]) -> None:
        """Transforms the findings into a format that can be written to a CSV file.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        for finding in findings:
            finding_dict = copy.deepcopy(finding.dict())
            finding_dict["compliance"] = unroll_dict(finding.compliance)
            finding_dict["account_tags"] = unroll_list(finding.account_tags)
            self._data.append(finding_dict)

    def write_to_file(self, file_descriptor) -> None:
        """Writes the findings to a CSV file.

        Args:
            file_descriptor (TextIOWrapper): a file descriptor

        """
        csv_writer = DictWriter(
            file_descriptor,
            fieldnames=self._data[0].keys(),
            delimiter=";",
        )
        for finding in self._data:
            csv_writer.writerow(finding)
