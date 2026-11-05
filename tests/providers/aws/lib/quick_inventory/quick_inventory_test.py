import csv
from unittest.mock import MagicMock

from prowler.providers.aws.lib.quick_inventory.quick_inventory import create_output


def _args(tmp_path):
    args = MagicMock()
    args.output_directory = str(tmp_path)
    args.output_filename = "inventory"
    return args


def _provider():
    provider = MagicMock()
    provider.identity.account = "123456789012"
    return provider


def _rows(tmp_path):
    with open(tmp_path / "inventory.csv", newline="") as handle:
        return list(csv.reader(handle))


class TestQuickInventoryCsvOutput:
    def test_formula_initiator_in_tags_is_neutralised(self, tmp_path):
        resources = [
            {
                "arn": "arn:aws:s3:eu-west-1:123456789012:bucket-one",
                "tags": '=cmd|" /C calc"!A0',
            }
        ]

        create_output(resources, _provider(), _args(tmp_path))

        header, row = _rows(tmp_path)
        assert row[header.index("AWS_Tags")] == '\'=cmd|" /C calc"!A0'

    def test_header_and_ordinary_values_are_untouched(self, tmp_path):
        resources = [
            {
                "arn": "arn:aws:s3:eu-west-1:123456789012:bucket-one",
                "tags": "env=prod",
            }
        ]

        create_output(resources, _provider(), _args(tmp_path))

        header, row = _rows(tmp_path)
        assert header[0] == "AWS_AccountID"
        assert row[header.index("AWS_Tags")] == "env=prod"
        assert row[header.index("AWS_Region")] == "eu-west-1"
