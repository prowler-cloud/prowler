from csv import DictWriter
from functools import wraps
from pathlib import Path
from typing import Callable, List, Optional

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.outputs.utils import sanitize_csv_value


def _without_manual_requirements(compliance: Compliance) -> Compliance:
    """
    Returns the compliance framework without its manual requirements, the ones that map no checks.

    Parameters:
        - compliance (Compliance): A compliance model.

    Returns:
        - Compliance: A copy of the model that keeps only the requirements with checks.
    """
    return compliance.copy(
        update={
            "Requirements": [
                requirement
                for requirement in compliance.Requirements
                if requirement.Checks
            ]
        }
    )


def _emit_manual_requirements_once(transform: Callable) -> Callable:
    """
    Makes a formatter's transform emit the manual requirements once per writer.

    Every formatter appends the manual requirements of the framework after the rows of the
    findings it receives. A writer that streams the findings in batches calls transform once
    per batch, so each manual requirement was written once per batch instead of once per output.

    The transform it returns accepts include_manual, the flag the universal exporters use.
    When the caller does not pass it, the writer decides from its own state: the first batch
    it transforms carries the manual requirements and the rest do not. The state lives in the
    writer because a writer created with no findings has not transformed anything yet, so the
    first batch it receives later still has to carry them.

    Without the manual requirements, transform receives the framework without them. They map
    no checks, so the rows of the findings do not change.

    Parameters:
        - transform (Callable): The transform method of a compliance formatter.

    Returns:
        - Callable: The transform method, emitting the manual requirements once per writer.
    """

    @wraps(transform)
    def guarded_transform(
        self,
        findings,
        compliance,
        *args,
        include_manual: Optional[bool] = None,
        **kwargs,
    ):
        if include_manual is None:
            include_manual = not self._manual_requirements_emitted
        if not include_manual:
            compliance = _without_manual_requirements(compliance)
        result = transform(self, findings, compliance, *args, **kwargs)
        if include_manual:
            self._manual_requirements_emitted = True
        return result

    return guarded_transform


class ComplianceOutput(Output):
    """
    This class represents an abstract base class for defining different types of outputs for findings.

    Attributes:
        _data (list): A list to store transformed data from findings.
        _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.
        _manual_requirements_emitted (bool): Whether transform already emitted the manual requirements.

    Methods:
        __init__: Initializes the Output class with findings, optionally creates a file descriptor.
        data: Property to access the transformed data.
        file_descriptor: Property to access the file descriptor.
        transform: Abstract method to transform findings into a specific format.
        batch_write_data_to_file: Abstract method to write data to a file in batches.
        create_file_descriptor: Method to create a file descriptor for writing data to a file.
    """

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        # Guard transform here so that every formatter, current or new, emits the manual
        # requirements once per writer without repeating the check in each of them.
        if "transform" in cls.__dict__:
            cls.transform = _emit_manual_requirements_once(cls.__dict__["transform"])

    def __init__(
        self,
        findings: List[Finding],
        compliance: Compliance,
        file_path: str = None,
        file_extension: str = "",
        from_cli: bool = True,
    ) -> None:
        # TODO: This class needs to be refactored to use the Output class init, methods and properties
        self._data = []
        self._manual_requirements_emitted = False
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
            ):
                if self._data:
                    csv_writer = DictWriter(
                        self._file_descriptor,
                        fieldnames=[
                            field.upper() for field in self._data[0].dict().keys()
                        ],
                        delimiter=";",
                    )
                    if self._file_descriptor.tell() == 0:
                        csv_writer.writeheader()
                    for finding in self._data:
                        csv_writer.writerow(
                            {
                                k.upper(): sanitize_csv_value(v)
                                for k, v in finding.dict().items()
                            }
                        )
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
