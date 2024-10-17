from json import dump
from os import SEEK_SET
from typing import Optional

from pydantic import BaseModel, validator

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.utils.utils import hash_sha512


class ASFF(Output):
    """
    ASFF class represents a transformation of findings into AWS Security Finding Format (ASFF).

    This class provides methods to transform a list of findings into the ASFF format required by AWS Security Hub. It includes operations such as generating unique identifiers, formatting timestamps, handling compliance frameworks, and ensuring the status values match the allowed values in ASFF.

    Attributes:
        - _data: A list to store the transformed findings.
        - _file_descriptor: A file descriptor to write to file.

    Methods:
        - transform(findings: list[Finding]) -> None: Transforms a list of findings into ASFF format.
        - batch_write_data_to_file() -> None: Writes the findings data to a file in JSON ASFF format.
        - generate_status(status: str, muted: bool = False) -> str: Generates the ASFF status based on the provided status and muted flag.

    References:
        - AWS Security Hub API Reference: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
        - AWS Security Finding Format Syntax: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
    """

    def transform(self, findings: list[Finding]) -> None:
        """
        Transforms a list of findings into AWS Security Finding Format (ASFF).

        This method iterates over the list of findings provided as input and transforms each finding into the ASFF format required by AWS Security Hub. It performs several operations for each finding, including generating unique identifiers, formatting timestamps, handling compliance frameworks, and ensuring the status values match the allowed values in ASFF.

        Parameters:
            - findings (list[Finding]): A list of Finding objects representing the findings to be transformed.

        Returns:
            - None

        Notes:
            - The method skips findings with a status of "MANUAL" as it is not valid in SecurityHub.
            - It generates unique identifiers for each finding based on specific attributes.
            - It formats timestamps in the required ASFF format.
            - It handles compliance frameworks and associated standards for each finding.
            - It ensures that the finding status matches the allowed values in ASFF.

        References:
            - AWS Security Hub API Reference: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
            - AWS Security Finding Format Syntax: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
        """
        try:
            for finding in findings:
                # MANUAL status is not valid in SecurityHub
                # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
                if finding.status == "MANUAL":
                    continue
                timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

                associated_standards, compliance_summary = ASFF.format_compliance(
                    finding.compliance
                )

                # Ensures finding_status matches allowed values in ASFF
                finding_status = ASFF.generate_status(finding.status, finding.muted)
                self._data.append(
                    AWSSecurityFindingFormat(
                        # The following line cannot be changed because it is the format we use to generate unique findings for AWS Security Hub
                        # If changed some findings could be lost because the unique identifier will be different
                        Id=f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}",
                        ProductArn=f"arn:{finding.partition}:securityhub:{finding.region}::product/prowler/prowler",
                        ProductFields=ProductFields(
                            ProwlerResourceName=finding.resource_uid,
                        ),
                        GeneratorId="prowler-" + finding.metadata.CheckID,
                        AwsAccountId=finding.account_uid,
                        Types=(
                            finding.metadata.CheckType
                            if finding.metadata.CheckType
                            else ["Software and Configuration Checks"]
                        ),
                        FirstObservedAt=timestamp,
                        UpdatedAt=timestamp,
                        CreatedAt=timestamp,
                        Severity=Severity(Label=finding.metadata.Severity.value),
                        Title=finding.metadata.CheckTitle,
                        Description=(
                            (finding.status_extended[:1000] + "...")
                            if len(finding.status_extended) > 1000
                            else finding.status_extended
                        ),
                        Resources=[
                            Resource(
                                Id=finding.resource_uid,
                                Type=finding.metadata.ResourceType,
                                Partition=finding.partition,
                                Region=finding.region,
                                Tags=finding.resource_tags,
                            )
                        ],
                        Compliance=Compliance(
                            Status=finding_status,
                            AssociatedStandards=associated_standards,
                            RelatedRequirements=compliance_summary,
                        ),
                        Remediation=Remediation(
                            Recommendation=Recommendation(
                                Text=finding.metadata.Remediation.Recommendation.Text,
                                Url=finding.metadata.Remediation.Recommendation.Url,
                            )
                        ),
                    )
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """
        Writes the findings data to a file in JSON ASFF format.

        This method iterates over the findings data stored in the '_data' attribute and writes it to the file descriptor '_file_descriptor' in JSON format. It starts by writing the JSON opening/header '[', then iterates over each finding, dumping it to the file with an indent of 4 spaces. After writing all findings, it writes the closing ']' to complete the JSON array structure. Finally, it closes the file descriptor.

        Returns:
            None
        """
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                # Write JSON opening/header [
                self._file_descriptor.write("[")

                # Write findings
                for finding in self._data:
                    dump(
                        finding.dict(exclude_none=True),
                        self._file_descriptor,
                        indent=4,
                    )
                    self._file_descriptor.write(",")

                # Write footer/closing ]
                if self._file_descriptor.tell() > 0:
                    if self._file_descriptor.tell() != 1:
                        self._file_descriptor.seek(
                            self._file_descriptor.tell() - 1, SEEK_SET
                        )
                    self._file_descriptor.truncate()
                    self._file_descriptor.write("]")

                # Close file descriptor
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def generate_status(status: str, muted: bool = False) -> str:
        """
        Generates the ASFF status based on the provided status and muted flag.

        Parameters:
            - status (str): The status of the finding.
            - muted (bool): Flag indicating if the finding is muted.

        Returns:
            - str: The ASFF status corresponding to the provided status and muted flag.

        References:
            - AWS Security Hub API Reference: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
        """
        json_asff_status = ""
        if muted:
            # Per AWS Security Hub "MUTED" is not a valid status
            # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
            json_asff_status = "WARNING"
        else:
            if status == "PASS":
                json_asff_status = "PASSED"
            elif status == "FAIL":
                json_asff_status = "FAILED"
            else:
                # MANUAL is set to NOT_AVAILABLE
                json_asff_status = "NOT_AVAILABLE"

        return json_asff_status

    @staticmethod
    def format_compliance(compliance: dict) -> tuple[list[dict], list[str]]:
        """
        Transforms a dictionary of compliance data into a tuple of associated standards and compliance summaries.

        Parameters:
            - compliance (dict): A dictionary containing compliance data where keys are standards and values are lists of compliance details.

        Returns:
            - tuple[list[dict], list[str]]: A tuple containing a list of associated standards (each as a dictionary with 'StandardsId') and a list of compliance summaries.

        Notes:
            - The method limits the number of associated standards to 20.
            - Each compliance summary is a concatenation of the standard key and its associated compliance details.
            - If the concatenated summary exceeds 64 characters, it is truncated to 63 characters.

        Example:
            format_compliance({"standard1": ["detail1", "detail2"], "standard2": ["detail3"]}) -> ([{"StandardsId": "standard1"}, {"StandardsId": "standard2"}], ["standard1 detail1 detail2", "standard2 detail3"])
        """
        compliance_summary = []
        associated_standards = []
        for key, value in compliance.items():
            if (
                len(associated_standards) < 20
            ):  # AssociatedStandards should NOT have more than 20 items
                associated_standards.append({"StandardsId": key})
                item = f"{key} {' '.join(value)}"
                if len(item) > 64:
                    item = item[0:63]
                compliance_summary.append(item)
        return associated_standards, compliance_summary


class ProductFields(BaseModel):
    """
    Class representing the Product Fields of a finding in the AWS Security Finding Format.

    Attributes:
        - ProviderName (str): The name of the provider, default value is "Prowler".
        - ProviderVersion (str): The version of the provider, fetched from the prowler_version in config.py.
        - ProwlerResourceName (str): The name of the Prowler resource.
    """

    ProviderName: str = "Prowler"
    ProviderVersion: str = prowler_version
    ProwlerResourceName: str


class Severity(BaseModel):
    """
    Class representing the severity of a finding in the AWS Security Finding Format.

    Attributes:
        - Label (str): A string representing the severity label of the finding.

    This class is used to define the severity level of a finding in the AWS Security Finding Format.
    """

    Label: str

    @validator("Label", pre=True, always=True)
    def severity_uppercase(severity):
        return severity.upper()


class Resource(BaseModel):
    """
    Class representing a resource in the AWS Security Finding Format.

    Attributes:
        - Type (str): The type of the resource.
        - Id (str): The unique identifier of the resource.
        - Partition (str): The partition where the resource resides.
        - Region (str): The region where the resource is located.
        - Tags (Optional[dict]): Optional dictionary of tags associated with the resource.

    This class defines the structure of a resource within the AWS Security Finding Format. It includes attributes to specify the type, unique identifier, partition, region, and optional tags of the resource.
    """

    Type: str
    Id: str
    Partition: str
    Region: str
    Tags: Optional[dict]

    @validator("Tags", pre=True, always=True)
    def tags_cannot_be_empty_dict(tags):
        if not tags:
            return None
        return tags


class Compliance(BaseModel):
    """
    Class representing the compliance details of a finding in the AWS Security Finding Format.

    Attributes:
        - Status (str): The compliance status of the finding.
        - RelatedRequirements (list[str]): A list of related compliance requirements for the finding.
        - AssociatedStandards (list[dict]): A list of associated standards with the finding, where each item is a dictionary containing the 'StandardsId'.

    This class defines the structure of compliance information within the AWS Security Finding Format. It includes attributes to specify the compliance status, related requirements, and associated standards of a finding.
    """

    Status: str
    RelatedRequirements: list[str]
    AssociatedStandards: list[dict]

    @validator("Status", pre=True, always=True)
    def status(status):
        if status not in ["PASSED", "WARNING", "FAILED", "NOT_AVAILABLE"]:
            raise ValueError("must contain a space")
        return status


class Recommendation(BaseModel):
    """
    Class representing a recommendation for remediation in the AWS Security Finding Format.

    Attributes:
        - Text (str): The text description of the recommendation.
        - Url (str): The URL link for additional information related to the recommendation.

    This class defines the structure of a recommendation within the AWS Security Finding Format. It includes attributes to specify the text description and URL link for further details regarding the recommendation.
    """

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
    """
    Class representing a remediation action in the AWS Security Finding Format.

    Attributes:
        - Recommendation (Recommendation): An instance of the Recommendation class providing details for remediation.

    This class defines the structure of a remediation action within the AWS Security Finding Format. It includes an attribute to specify the recommendation for remediation, which is an instance of the Recommendation class.
    """

    Recommendation: Recommendation


class AWSSecurityFindingFormat(BaseModel):
    """
    AWSSecurityFindingFormat generates a finding's output in JSON ASFF format: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html

    Attributes:
        - SchemaVersion (str): The version of the ASFF schema being used, default value is "2018-10-08".
        - Id (str): The unique identifier of the finding.
        - ProductArn (str): The ARN of the product generating the finding.
        - RecordState (str): The state of the finding record, default value is "ACTIVE".
        - ProductFields (ProductFields): An instance of the ProductFields class representing the product fields of the finding.
        - GeneratorId (str): The ID of the generator.
        - AwsAccountId (str): The AWS account ID associated with the finding.
        - Types (list[str]): A list of types associated with the finding, default value is None.
        - FirstObservedAt (str): The timestamp when the finding was first observed.
        - UpdatedAt (str): The timestamp when the finding was last updated.
        - CreatedAt (str): The timestamp when the finding was created.
        - Severity (Severity): An instance of the Severity class representing the severity of the finding.
        - Title (str): The title of the finding.
        - Description (str): The description of the finding, truncated to 1024 characters if longer.
        - Resources (list[Resource]): A list of resources associated with the finding, default value is None.
        - Compliance (Compliance): An instance of the Compliance class representing the compliance details of the finding.
        - Remediation (Remediation): An instance of the Remediation class providing details for remediation.

    This class defines the structure of a finding in the AWS Security Finding Format, including various attributes such as schema version, identifiers, timestamps, severity, title, description, resources, compliance details, and remediation information.
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
