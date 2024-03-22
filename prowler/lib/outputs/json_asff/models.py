from typing import Optional

from pydantic import BaseModel, validator

from prowler.config.config import prowler_version


class ProductFields(BaseModel):
    ProviderName: str = "Prowler"
    ProviderVersion: str = prowler_version
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


class Recommendation(BaseModel):
    Text: str = ""
    Url: str = ""

    @validator("Text", pre=True, always=True)
    def text_must_not_exceed_512_chars(text):
        text_validated = text
        if len(text) > 512:
            text_validated = text[:509] + "..."
        return text_validated

    @validator("Url", pre=True, always=True)
    def set_default_url_if_empty(url):
        default_url = "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
        if url:
            default_url = url
        return default_url


class Remediation(BaseModel):
    Recommendation: Recommendation


class Check_Output_JSON_ASFF(BaseModel):
    """
    Check_Output_JSON_ASFF generates a finding's output in JSON ASFF format: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
    """

    SchemaVersion: str = "2018-10-08"
    Id: str
    ProductArn: str
    RecordState: str = "ACTIVE"
    ProductFields: ProductFields
    GeneratorId: str
    AwsAccountId: str
    Types: list[str] = None
    FirstObservedAt: str
    UpdatedAt: str
    CreatedAt: str
    Severity: Severity
    Title: str
    Description: str
    Resources: list[Resource] = None
    Compliance: Compliance
    Remediation: Remediation

    @validator("Description", pre=True, always=True)
    def description_must_not_exceed_1024_chars(description):
        description_validated = description
        if len(description) > 1024:
            description_validated = description[:1021] + "..."
        return description_validated
