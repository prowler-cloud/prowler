from prowler.providers.common.arguments import (
    validate_asff_usage,
    validate_sarif_usage,
)


class TestValidateAsffUsage:
    def test_asff_with_aws_provider(self):
        valid, msg = validate_asff_usage("aws", ["json-asff"])
        assert valid is True
        assert msg == ""

    def test_asff_with_non_aws_provider(self):
        valid, msg = validate_asff_usage("gcp", ["json-asff"])
        assert valid is False
        assert "aws" in msg

    def test_no_asff_in_formats(self):
        valid, msg = validate_asff_usage("gcp", ["csv", "html"])
        assert valid is True

    def test_no_output_formats(self):
        valid, msg = validate_asff_usage("aws", None)
        assert valid is True


class TestValidateSarifUsage:
    def test_sarif_with_iac_provider(self):
        valid, msg = validate_sarif_usage("iac", ["sarif"])
        assert valid is True
        assert msg == ""

    def test_sarif_with_non_iac_provider(self):
        valid, msg = validate_sarif_usage("aws", ["sarif"])
        assert valid is False
        assert "iac" in msg

    def test_sarif_with_other_provider(self):
        valid, msg = validate_sarif_usage("gcp", ["csv", "sarif"])
        assert valid is False
        assert "gcp" in msg

    def test_no_sarif_in_formats(self):
        valid, msg = validate_sarif_usage("aws", ["csv", "html"])
        assert valid is True

    def test_no_output_formats(self):
        valid, msg = validate_sarif_usage("iac", None)
        assert valid is True

    def test_empty_output_formats(self):
        valid, msg = validate_sarif_usage("aws", [])
        assert valid is True
