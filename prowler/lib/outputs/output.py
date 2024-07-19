from abc import ABC, abstractmethod
from io import TextIOWrapper
from pathlib import Path
from typing import List

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.utils.utils import open_file


class Output(ABC):
    """
    This class represents an abstract base class for defining different types of outputs for findings.

    Attributes:
        _data (list): A list to store transformed data from findings.
        _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.
        _file_extension (str): The extension of the file with the leading ., e.g.: .csv

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
    _file_extension: str

    def __init__(
        self,
        findings: List[Finding],
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
            self.transform(findings)
            if create_file_descriptor and file_path:
                self.create_file_descriptor(file_path)

    @property
    def data(self):
        return self._data

    @property
    def file_descriptor(self):
        return self._file_descriptor

    @file_descriptor.setter
    def file_descriptor(self, file_descriptor: TextIOWrapper):
        self._file_descriptor = file_descriptor

    @property
    def file_extension(self):
        return self._file_extension

    @abstractmethod
    def transform(self, findings: List[Finding]):
        raise NotImplementedError

    @abstractmethod
    def batch_write_data_to_file(self) -> None:
        raise NotImplementedError

    def create_file_descriptor(self, file_path: str) -> None:
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
