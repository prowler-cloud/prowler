from abc import ABC, abstractmethod
from io import TextIOWrapper
from typing import List

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.utils.utils import open_file


class Output(ABC):
    _data: list[Finding]
    _file_descriptor: TextIOWrapper

    def __init__(
        self,
        findings: List[Finding],
        create_file_descriptor: bool = False,
        file_path: str = None,
    ) -> None:
        self._data = []
        self.transform(findings)
        if create_file_descriptor:
            self.create_file_descriptor(file_path)

    @property
    def data(self):
        return self._data

    @property
    def file_descriptor(self):
        return self._file_descriptor

    @abstractmethod
    def transform(self, findings: List[Finding]):
        raise NotImplementedError

    @abstractmethod
    def batch_write_data_to_file(self, file_descriptor: TextIOWrapper) -> None:
        raise NotImplementedError

    def create_file_descriptor(self, file_path) -> None:
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
