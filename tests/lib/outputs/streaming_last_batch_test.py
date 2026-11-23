import json

import pytest

from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.ocsf.ocsf import OCSF
from tests.lib.outputs.compliance.fixtures import NIST_800_53_REVISION_4_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


def _finding():
    return generate_finding_output(compliance={"NIST-800-53-Revision-4": "ac_2_4"})


def _stream_then_empty_last_batch(writer, retransform):
    writer.close_file = False
    writer.batch_write_data_to_file()
    writer._data.clear()

    retransform([])
    writer.close_file = True
    writer.batch_write_data_to_file()


class TestEmptyLastBatchFinalizesFile:
    def test_csv_is_closed_with_every_row(self, tmp_path):
        path = tmp_path / "out"
        writer = CSV(
            findings=[_finding()],
            file_path=str(path),
            file_extension=".csv",
            from_cli=False,
        )

        _stream_then_empty_last_batch(writer, writer.transform)

        assert writer._file_descriptor.closed
        assert len((tmp_path / "out.csv").read_text().splitlines()) == 2

    def test_ocsf_is_closed_as_a_valid_json_array(self, tmp_path):
        path = tmp_path / "out"
        writer = OCSF(
            findings=[_finding()],
            file_path=str(path),
            file_extension=".ocsf.json",
            from_cli=False,
        )

        _stream_then_empty_last_batch(writer, writer.transform)

        assert writer._file_descriptor.closed
        assert len(json.loads((tmp_path / "out.ocsf.json").read_text())) == 1

    def test_compliance_csv_is_closed_with_every_row(self, tmp_path):
        path = tmp_path / "out_nist.csv"
        writer = GenericCompliance(
            findings=[_finding()],
            compliance=NIST_800_53_REVISION_4_AWS,
            file_path=str(path),
            from_cli=False,
        )
        rows_first_batch = len(writer._data)

        # A framework without manual requirements adds no rows for an empty batch.
        _stream_then_empty_last_batch(writer, lambda findings: None)

        assert writer._file_descriptor.closed
        assert len(path.read_text().splitlines()) == rows_first_batch + 1

    @pytest.mark.parametrize("extension", [".csv", ".ocsf.json"])
    def test_no_findings_leaves_an_empty_closed_file(self, tmp_path, extension):
        cls = CSV if extension == ".csv" else OCSF
        writer = cls(
            findings=[],
            file_path=str(tmp_path / "out"),
            file_extension=extension,
            from_cli=False,
        )
        if not writer._file_descriptor:
            writer.create_file_descriptor(writer.file_path)
        writer.close_file = True

        writer.batch_write_data_to_file()

        assert writer._file_descriptor.closed
        assert (tmp_path / f"out{extension}").read_text() == ""
