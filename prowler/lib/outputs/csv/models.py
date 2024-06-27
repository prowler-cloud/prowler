import copy
from csv import DictWriter

from prowler.lib.logger import logger
from prowler.lib.outputs.output import Finding, Output
from prowler.lib.outputs.utils import unroll_dict, unroll_list


class CSV(Output):
    def transform(self, findings: list[Finding]) -> None:
        """Transforms the findings into a format that can be written to a CSV file.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        try:
            for finding in findings:
                finding_dict = copy.deepcopy(finding.dict())
                finding_dict["compliance"] = unroll_dict(finding.compliance)
                finding_dict["account_tags"] = unroll_list(finding.account_tags)
                self._data.append(finding_dict)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_findings_to_file(self) -> None:
        """Writes the findings to a CSV file.

        Args:
            file_descriptor (TextIOWrapper): a file descriptor

        """
        try:
            if self._file_descriptor:
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=self._data[0].keys(),
                    delimiter=";",
                )
                for finding in self._data:
                    csv_writer.writerow(finding)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
