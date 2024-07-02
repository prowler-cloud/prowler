from typing import List

from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output


class OCSF(Output):
    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into the OCSF format.

        Args:
            findings (List[Finding]): a list of Finding objects
        """

    def batch_write_data_to_file(self, file_descriptor) -> None:
        """Writes the findings to a file using the OCSF format using the `Output._file_descriptor`."""
