from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


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


class CSVRow(BaseModel):
    """
    CSVRow generates a finding's output in CSV format.

    This is the base CSV output model for every provider.
    """

    auth_method: str
    timestamp: datetime
    account_uid: str
    # Optional since depends on permissions
    account_name: Optional[str]
    # Optional since depends on permissions
    account_email: Optional[str]
    # Optional since depends on permissions
    account_organization_uid: Optional[str]
    # Optional since depends on permissions
    account_organization: Optional[str]
    # Optional since depends on permissions
    account_tags: Optional[str]
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
    compliance: str
    categories: str
    depends_on: str
    related_to: str
    notes: str
