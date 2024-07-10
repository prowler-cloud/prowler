from io import TextIOWrapper
from typing import List

from prowler.lib.check.compliance_models import ComplianceBaseModel
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

    _data: list
    _file_descriptor: TextIOWrapper

    def __init__(
        self,
        findings: List[Finding],
        compliance: ComplianceBaseModel,
        create_file_descriptor: bool = False,
        file_path: str = None,
    ) -> None:
        self._data = []
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
