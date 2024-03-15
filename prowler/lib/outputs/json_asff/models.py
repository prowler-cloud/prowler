from typing import Optional

from pydantic import BaseModel


class ProductFields(BaseModel):
    ProviderName: str = "Prowler"
    ProviderVersion: str
    ProwlerResourceName: str


class Severity(BaseModel):
    Label: str


class Resource(BaseModel):
    Type: str
    Id: str
    Partition: str
    Region: str
    Tags: Optional[dict]


class Compliance(BaseModel):
    Status: str
    RelatedRequirements: list[str]
    AssociatedStandards: list[dict]


class Check_Output_JSON_ASFF(BaseModel):
    """
    Check_Output_JSON_ASFF generates a finding's output in JSON ASFF format: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
    """

    SchemaVersion: str = "2018-10-08"
    Id: str = ""
    ProductArn: str = ""
    RecordState: str = "ACTIVE"
    ProductFields: ProductFields = None  # type: ignore
    GeneratorId: str = ""
    AwsAccountId: str = ""
    Types: list[str] = None
    FirstObservedAt: str = ""
    UpdatedAt: str = ""
    CreatedAt: str = ""
    Severity: Severity = None  # type: ignore
    Title: str = ""
    Description: str = ""
    Resources: list[Resource] = None
    Compliance: Compliance = None  # type: ignore
    Remediation: dict = None
