from abc import ABC, abstractmethod
from io import TextIOWrapper
from typing import List

from prowler.lib.check.compliance_models import ComplianceBaseModel
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.utils.utils import open_file


class ComplianceOutput(ABC):
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
            self.transform(findings, compliance)
            if create_file_descriptor:
                self.create_file_descriptor(file_path)

    @property
    def data(self):
        return self._data

    @property
    def file_descriptor(self):
        return self._file_descriptor

    @abstractmethod
    def transform(self, findings: List[Finding], compliance: dict):
        raise NotImplementedError

    @abstractmethod
    def batch_write_data_to_file(self, file_descriptor: TextIOWrapper) -> None:
        raise NotImplementedError

    def create_file_descriptor(self, file_path) -> None:
        """
        Creates a file descriptor for writing data to a file.

        Parameters:
            file_path (str): The path to the file where the data will be written.

        Returns:
            None

        Raises:
            Any exception that occurs during the file creation process will be caught and logged using the logger.

        Note:
            The file is opened in append mode ("a") to ensure data is written at the end of the file without overwriting existing content.
        """
        try:
            mode = "a"
            self._file_descriptor = open_file(
                file_path,
                mode,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
