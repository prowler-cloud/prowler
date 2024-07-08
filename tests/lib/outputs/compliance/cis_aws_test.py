from io import StringIO

from mock import patch

from prowler.lib.outputs.compliance.cis_aws import AWSCIS
from prowler.lib.outputs.compliance.models import AWS
from tests.lib.outputs.compliance.fixtures import CIS_1_4_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class Test_AWSCIS:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"CIS-1.4": "2.1.3"})]

        output = AWSCIS(findings, CIS_1_4_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, AWS)

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={"CIS-1.4": "2.1.3"})]
        # Clear the data from CSV class
        output = AWSCIS(findings, CIS_1_4_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        content = content.removeprefix("\r\n")
        content = content.removesuffix("\r\n")
        assert CIS_1_4_AWS.Description in content
