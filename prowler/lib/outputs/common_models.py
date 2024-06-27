import copy
from abc import ABC, abstractmethod
from csv import DictWriter
from datetime import datetime
from enum import Enum
from io import TextIOWrapper
from typing import Optional, Union

from pydantic import BaseModel

from prowler.config.config import prowler_version
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
        for finding in findings:
            finding_dict = copy.deepcopy(finding.dict())
            finding_dict["compliance"] = unroll_dict(finding.compliance)
            finding_dict["account_tags"] = unroll_list(finding.account_tags)
            self._data.append(finding_dict)

    def write_to_file(self, file_descriptor) -> None:
        csv_writer = DictWriter(
            file_descriptor,
            fieldnames=self._data[0].keys(),
            delimiter=";",
        )
        for finding in self._data:
            csv_writer.writerow(finding)
