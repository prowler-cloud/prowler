from typer.testing import CliRunner

from cli.cli import app

runner = CliRunner()


class TestCLI:
    def test_banner_show(self):
        result = runner.invoke(app, ["banner", "--show"])
        assert result.exit_code == 0
        assert "Banner is not shown." not in result.output

    def test_banner_no_show(self):
        result = runner.invoke(app, ["banner", "--no-show"])
        assert result.exit_code == 0
        assert "Banner is not shown." in result.output

    def test_list_services_aws(self):
        result = runner.invoke(app, ["aws", "list-services"])
        assert result.exit_code == 0
        assert "available services." in result.output

    def test_list_fixers_aws(self):
        result = runner.invoke(app, ["aws", "list-fixers"])
        assert result.exit_code == 0
        assert "available fixers." in result.output

    def test_list_categories_aws(self):
        result = runner.invoke(app, ["aws", "list-categories"])
        assert result.exit_code == 0
        assert "available categories." in result.output

    def test_list_compliance_aws():
        result = runner.invoke(app, ["aws", "list-compliance"])
        assert result.exit_code == 0
        assert "available Compliance Frameworks." in result.output

    def test_list_compliance_requirements_aws():
        result = runner.invoke(
            app, ["aws", "list-compliance-requirements", "cis_2.0_aws", "soc2_aws"]
        )
        assert result.exit_code == 0
        assert "Listing CIS 2.0 AWS Compliance Requirements:" in result.output
        assert "Listing SOC2  AWS Compliance Requirements:" in result.output

    def test_list_compliance_requirements_no_compliance_aws():
        result = runner.invoke(app, ["aws", "list-compliance-requirements"])
        assert result.exit_code == 2
        assert "Expected at least one" in result.output

    def test_list_compliance_requirements_one_invalid_aws():
        invalid_name = "invalid"
        result = runner.invoke(
            app, ["aws", "list-compliance-requirements", "cis_2.0_aws", invalid_name]
        )
        assert result.exit_code == 0
        assert "Listing CIS 2.0 AWS Compliance Requirements:" in result.output
        assert f"{invalid_name} is not a valid Compliance Framework" in result.output

    def test_list_checks_aws():
        result = runner.invoke(app, ["aws", "list-checks"])
        assert result.exit_code == 0
        assert "available checks." in result.output

    def test_list_checks_json_aws():
        result = runner.invoke(app, ["aws", "list-checks-json"])
        assert result.exit_code == 0
        assert "aws" in result.output
        assert result.output.startswith("{") and result.output.endswith("}\n")
