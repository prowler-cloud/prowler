from io import StringIO

from mock import patch

from prowler.lib.outputs.compliance.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.models import GCP
from tests.lib.outputs.compliance.fixtures import CIS_2_0_GCP
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class Test_GCPCIS:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"CIS-2.0": "2.13"})]

        output = GCPCIS(findings, CIS_2_0_GCP)
        output_data = output.data[0]
        assert isinstance(output_data, GCP)

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={"CIS-2.0": "2.13"})]
        # Clear the data from CSV class
        output = GCPCIS(findings, CIS_2_0_GCP)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        content = content.removeprefix("\r\n")
        content = content.removesuffix("\r\n")
        assert CIS_2_0_GCP.Description in content
