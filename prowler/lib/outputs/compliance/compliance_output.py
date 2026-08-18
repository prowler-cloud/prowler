from csv import DictWriter
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Type, Union
from pydantic.v1 import BaseModel
from prowler.config.config import timestamp
from prowler.lib.check.compliance_config_eval import (
    apply_config_status,
    build_requirement_config_status,
)

from prowler.lib.check.compliance_models import (
    Compliance,
    Mitre_Requirement,
    Compliance_Requirement,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output


class ComplianceOutput(Output):
    """
    This class represents an abstract base class for defining different types of outputs for findings.

    Attributes:
        _data (list): A list to store transformed data from findings.
        _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        __init__: Initializes the Output class with findings, optionally creates a file descriptor.
        data: Property to access the transformed data.
        file_descriptor: Property to access the file descriptor.
        transform: Abstract method to transform findings into a specific format.
        batch_write_data_to_file: Abstract method to write data to a file in batches.
        create_file_descriptor: Method to create a file descriptor for writing data to a file.
    """

    def __init__(
        self,
        findings: List[Finding],
        compliance: Compliance,
        file_path: str = None,
        file_extension: str = "",
        from_cli: bool = True,
    ) -> None:
        # TODO: This class needs to be refactored to use the Output class init, methods and properties
        """Initialize compliance output instance."""
        self._data = []
        self.close_file = False
        self.file_path = file_path
        self.file_descriptor = None
        # This parameter is to avoid refactoring more code, the CLI does not write in batches, the API does
        self._from_cli = from_cli

        if not file_extension and file_path:
            # Compliance reports are always CSV, so just use the last suffix
            # e.g., "cis_5.0_aws.csv" should have extension ".csv", not ".0_aws.csv"
            path_obj = Path(file_path)
            self._file_extension = path_obj.suffix if path_obj.suffix else ""
        if file_extension:
            self._file_extension = file_extension
            self.file_path = f"{file_path}{self.file_extension}"

        if findings:
            # Get the compliance name of the model
            compliance_name = (
                compliance.Framework + "-" + compliance.Version
                if compliance.Version
                else compliance.Framework
            )
            self.transform(findings, compliance, compliance_name)
            if not self._file_descriptor and file_path:
                self.create_file_descriptor(self.file_path)

    def batch_write_data_to_file(self) -> None:
        """
        Writes the findings data to a CSV file in the specific compliance format.

        Returns:
            - None
        """
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=[field.upper() for field in self._data[0].dict().keys()],
                    delimiter=";",
                )
                if self._file_descriptor.tell() == 0:
                    csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(
                        {k.upper(): v for k, v in finding.dict().items()}
                    )
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ComplianceOutputBase(ComplianceOutput):
    """
    Base class for specific compliance outputs to eliminate duplicated transform logic.
    Subclasses only need to implement `provider_identity_fields(finding)` and define
    which `BaseModel` to use.
    """

    @property
    @abstractmethod
    def model(self) -> Type[BaseModel]:
        """Must return the specific pydantic model class.

        Returns:
            Type[BaseModel]: The pydantic model class used for serialization.
        """
        raise NotImplementedError

    @abstractmethod
    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns a dictionary with provider-specific identity fields.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None for manual checks.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        raise NotImplementedError

    def get_framework_specific_fields(
        self, requirement: Union[Mitre_Requirement, Compliance_Requirement]
    ) -> dict[str, str]:
        """Subclass hook to provide framework-specific fields from the requirement.
        
        Args:
            requirement (Union[Mitre_Requirement, Compliance_Requirement]): The compliance requirement to extract framework-specific data from.
            
        Returns:
            dict[str, str]: A dictionary containing framework-specific fields to be appended to the model.
        """
        return {}

    def _get_attribute_fields(self, attribute: Any) -> dict[str, Any]:
        """Convert requirement attribute fields to model attribute mapping.

        Args:
            attribute (Any): The compliance requirement attribute.

        Returns:
            dict[str, Any]: Mapped attribute dictionary.
        """
        attribute_fields = {}
        for k, v in attribute.dict().items():
            field_name = f"Requirements_Attributes_{k}"
            expected_type = None
            if hasattr(self.model, "__fields__") and field_name in self.model.__fields__:
                field_obj = self.model.__fields__[field_name]
                expected_type = getattr(field_obj, "outer_type_", None)
            elif hasattr(self.model, "model_fields") and field_name in self.model.model_fields:
                field_obj = self.model.model_fields[field_name]
                expected_type = getattr(field_obj, "annotation", None)

            if expected_type and getattr(expected_type, "__origin__", expected_type) == list:
                val = v
            else:
                val = v if not isinstance(v, list) else ",".join(v)

            attribute_fields[field_name] = val
        return attribute_fields

    def transform(
        self,
        findings: List[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """Transforms a list of findings into compliance format based on the specific framework requirements.

        Args:
            findings (List[Finding]): The list of findings to transform.
            compliance (Compliance): The compliance framework definition.
            compliance_name (str): The name of the compliance framework.

        Returns:
            None
        """

        requirement_config_status = build_requirement_config_status(
            compliance.Requirements
        )

        provider = findings[0].provider if findings else compliance.Provider.lower()

        for finding in findings:
            for requirement in compliance.Requirements:
                if finding.check_id in requirement.Checks:
                    row_status, row_status_extended = apply_config_status(
                        finding.status,
                        finding.status_extended,
                        requirement_config_status.get(requirement.Id),
                    )
                    for attribute in requirement.Attributes:
                        provider_fields = self.provider_identity_fields(finding)
                        attribute_fields = self._get_attribute_fields(attribute)
                        framework_fields = self.get_framework_specific_fields(
                            requirement
                        )

                        compliance_row = self.model(
                            Provider=provider,
                            Description=compliance.Description,
                            **provider_fields,
                            AssessmentDate=str(timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Description=requirement.Description,
                            **attribute_fields,
                            Status=row_status,
                            StatusExtended=row_status_extended,
                            ResourceId=finding.resource_uid,
                            ResourceName=finding.resource_name,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                            Framework=compliance.Framework,
                            Name=compliance.Name,
                            **framework_fields,
                        )
                        self._data.append(compliance_row)

        # Add manual requirements
        for requirement in compliance.Requirements:
            if not requirement.Checks:
                for attribute in requirement.Attributes:
                    provider_fields = self.provider_identity_fields(None)
                    attribute_fields = self._get_attribute_fields(attribute)
                    framework_fields = self.get_framework_specific_fields(
                        requirement
                    )

                    compliance_row = self.model(
                        Provider=provider,
                        Description=compliance.Description,
                        **provider_fields,
                        AssessmentDate=str(timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        **attribute_fields,
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                        Framework=compliance.Framework,
                        Name=compliance.Name,
                        **framework_fields,
                    )
                    self._data.append(compliance_row)
