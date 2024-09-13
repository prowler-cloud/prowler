from csv import DictWriter
from pathlib import Path
from typing import List

from prowler.lib.check.compliance_models import Compliance
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
        create_file_descriptor: bool = False,
        file_path: str = None,
        file_extension: str = "",
    ) -> None:
        self._data = []

        if not file_extension and file_path:
            self._file_extension = "".join(Path(file_path).suffixes)
        if file_extension:
            self._file_extension = file_extension

        if findings:
            # Get the compliance name of the model
            compliance_name = (
                compliance.Framework + "-" + compliance.Version
                if compliance.Version
                else compliance.Framework
            )
            self.transform(findings, compliance, compliance_name)
            if create_file_descriptor:
                self.create_file_descriptor(file_path)

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
                csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(
                        {k.upper(): v for k, v in finding.dict().items()}
                    )
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
