from csv import DictWriter

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.outputs.utils import unroll_dict


class CSV(Output):
    def transform(self, findings: list[Finding]) -> None:
        """Transforms the findings into the CSV format.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        try:
            for finding in findings:
                finding_dict = {k.upper(): v for k, v in finding.dict().items()}
                finding_dict["RESOURCE_TAGS"] = unroll_dict(finding.resource_tags)
                finding_dict["COMPLIANCE"] = unroll_dict(
                    finding.compliance, separator=": "
                )
                finding_dict["ACCOUNT_TAGS"] = unroll_dict(
                    finding.account_tags, separator=":"
                )
                finding_dict["STATUS"] = finding.status.value
                finding_dict["SEVERITY"] = finding.severity.value
                self._data.append(finding_dict)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Writes the findings to a file using the CSV format using the `Output._file_descriptor`."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=self._data[0].keys(),
                    delimiter=";",
                )
                csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(finding)
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
