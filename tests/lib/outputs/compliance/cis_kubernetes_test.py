from io import StringIO

from mock import patch

from prowler.lib.outputs.compliance.cis_kubernetes import KubernetesCIS
from prowler.lib.outputs.compliance.models import Kubernetes
from tests.lib.outputs.compliance.fixtures import CIS_1_8_KUBERNETES
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class Test_KubernetesCIS:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"CIS-1.8": "1.1.3"})]

        output = KubernetesCIS(findings, CIS_1_8_KUBERNETES)
        output_data = output.data[0]
        assert isinstance(output_data, Kubernetes)

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={"CIS-1.8": "1.1.3"})]
        # Clear the data from CSV class
        output = KubernetesCIS(findings, CIS_1_8_KUBERNETES)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        content = content.removeprefix("\r\n")
        content = content.removesuffix("\r\n")
        assert CIS_1_8_KUBERNETES.Description in content
