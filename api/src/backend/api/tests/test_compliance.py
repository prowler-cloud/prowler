from unittest.mock import patch, MagicMock

from api.compliance import (
    get_prowler_provider_checks,
    get_prowler_provider_compliance,
    load_prowler_compliance,
    load_prowler_checks,
    generate_scan_compliance,
    generate_compliance_overview_template,
)
from api.models import Provider


class TestCompliance:
    @patch("api.compliance.CheckMetadata")
    def test_get_prowler_provider_checks(self, mock_check_metadata):
        provider_type = Provider.ProviderChoices.AWS
        mock_check_metadata.get_bulk.return_value = {
            "check1": MagicMock(),
            "check2": MagicMock(),
            "check3": MagicMock(),
        }
        checks = get_prowler_provider_checks(provider_type)
        assert set(checks) == {"check1", "check2", "check3"}
        mock_check_metadata.get_bulk.assert_called_once_with(provider_type)

    @patch("api.compliance.Compliance")
    def test_get_prowler_provider_compliance(self, mock_compliance):
        provider_type = Provider.ProviderChoices.AWS
        mock_compliance.get_bulk.return_value = {
            "compliance1": MagicMock(),
            "compliance2": MagicMock(),
        }
        compliance_data = get_prowler_provider_compliance(provider_type)
        assert compliance_data == mock_compliance.get_bulk.return_value
        mock_compliance.get_bulk.assert_called_once_with(provider_type)

    @patch("api.models.Provider.ProviderChoices")
    @patch("api.compliance.get_prowler_provider_compliance")
    @patch("api.compliance.generate_compliance_overview_template")
    @patch("api.compliance.load_prowler_checks")
    def test_load_prowler_compliance(
        self,
        mock_load_prowler_checks,
        mock_generate_compliance_overview_template,
        mock_get_prowler_provider_compliance,
        mock_provider_choices,
    ):
        mock_provider_choices.values = ["aws", "azure"]

        compliance_data_aws = {"compliance_aws": MagicMock()}
        compliance_data_azure = {"compliance_azure": MagicMock()}

        compliance_data_dict = {
            "aws": compliance_data_aws,
            "azure": compliance_data_azure,
        }

        def mock_get_compliance(provider_type):
            return compliance_data_dict[provider_type]

        mock_get_prowler_provider_compliance.side_effect = mock_get_compliance

        mock_generate_compliance_overview_template.return_value = {
            "template_key": "template_value"
        }

        mock_load_prowler_checks.return_value = {"checks_key": "checks_value"}

        load_prowler_compliance()

        from api.compliance import PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE, PROWLER_CHECKS

        assert PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE == {
            "template_key": "template_value"
        }
        assert PROWLER_CHECKS == {"checks_key": "checks_value"}

        expected_prowler_compliance = compliance_data_dict
        mock_get_prowler_provider_compliance.assert_any_call("aws")
        mock_get_prowler_provider_compliance.assert_any_call("azure")
        mock_generate_compliance_overview_template.assert_called_once_with(
            expected_prowler_compliance
        )
        mock_load_prowler_checks.assert_called_once_with(expected_prowler_compliance)

    @patch("api.compliance.get_prowler_provider_checks")
    @patch("api.models.Provider.ProviderChoices")
    def test_load_prowler_checks(
        self, mock_provider_choices, mock_get_prowler_provider_checks
    ):
        mock_provider_choices.values = ["aws"]

        mock_get_prowler_provider_checks.return_value = ["check1", "check2", "check3"]

        prowler_compliance = {
            "aws": {
                "compliance1": MagicMock(
                    Requirements=[
                        MagicMock(
                            Checks=["check1", "check2"],
                        ),
                    ],
                ),
            },
        }

        expected_checks = {
            "aws": {
                "check1": {"compliance1"},
                "check2": {"compliance1"},
                "check3": set(),
            }
        }

        checks = load_prowler_checks(prowler_compliance)
        assert checks == expected_checks
        mock_get_prowler_provider_checks.assert_called_once_with("aws")

    @patch("api.compliance.PROWLER_CHECKS", new_callable=dict)
    def test_generate_scan_compliance(self, mock_prowler_checks):
        mock_prowler_checks["aws"] = {
            "check1": {"compliance1"},
            "check2": {"compliance1", "compliance2"},
        }

        compliance_overview = {
            "compliance1": {
                "requirements": {
                    "requirement1": {
                        "checks": {"check1": None, "check2": None},
                        "checks_status": {
                            "pass": 0,
                            "fail": 0,
                            "manual": 0,
                            "total": 2,
                        },
                        "status": "PASS",
                    }
                },
                "requirements_status": {"passed": 1, "failed": 0, "manual": 0},
            },
            "compliance2": {
                "requirements": {
                    "requirement2": {
                        "checks": {"check2": None},
                        "checks_status": {
                            "pass": 0,
                            "fail": 0,
                            "manual": 0,
                            "total": 1,
                        },
                        "status": "PASS",
                    }
                },
                "requirements_status": {"passed": 1, "failed": 0, "manual": 0},
            },
        }

        provider_type = "aws"
        check_id = "check2"
        status = "FAIL"

        generate_scan_compliance(compliance_overview, provider_type, check_id, status)

        assert (
            compliance_overview["compliance1"]["requirements"]["requirement1"][
                "checks"
            ]["check2"]
            == "FAIL"
        )
        assert (
            compliance_overview["compliance1"]["requirements"]["requirement1"][
                "checks_status"
            ]["fail"]
            == 1
        )
        assert (
            compliance_overview["compliance1"]["requirements"]["requirement1"]["status"]
            == "FAIL"
        )
        assert compliance_overview["compliance1"]["requirements_status"]["passed"] == 0
        assert compliance_overview["compliance1"]["requirements_status"]["failed"] == 1

        assert (
            compliance_overview["compliance2"]["requirements"]["requirement2"][
                "checks"
            ]["check2"]
            == "FAIL"
        )
        assert (
            compliance_overview["compliance2"]["requirements"]["requirement2"][
                "checks_status"
            ]["fail"]
            == 1
        )
        assert (
            compliance_overview["compliance2"]["requirements"]["requirement2"]["status"]
            == "FAIL"
        )
        assert compliance_overview["compliance2"]["requirements_status"]["passed"] == 0
        assert compliance_overview["compliance2"]["requirements_status"]["failed"] == 1

        assert (
            compliance_overview["compliance1"]["requirements"]["requirement1"][
                "checks"
            ]["check1"]
            is None
        )

    @patch("api.models.Provider.ProviderChoices")
    def test_generate_compliance_overview_template(self, mock_provider_choices):
        mock_provider_choices.values = ["aws"]

        requirement1 = MagicMock(
            Id="requirement1",
            Name="Requirement 1",
            Description="Description of requirement 1",
            Attributes=[],
            Checks=["check1", "check2"],
        )
        requirement2 = MagicMock(
            Id="requirement2",
            Name="Requirement 2",
            Description="Description of requirement 2",
            Attributes=[],
            Checks=[],
        )
        compliance1 = MagicMock(
            Requirements=[requirement1, requirement2],
            Framework="Framework 1",
            Version="1.0",
            Description="Description of compliance1",
        )
        prowler_compliance = {"aws": {"compliance1": compliance1}}

        template = generate_compliance_overview_template(prowler_compliance)

        expected_template = {
            "aws": {
                "compliance1": {
                    "framework": "Framework 1",
                    "version": "1.0",
                    "provider": "aws",
                    "description": "Description of compliance1",
                    "requirements": {
                        "requirement1": {
                            "name": "Requirement 1",
                            "description": "Description of requirement 1",
                            "attributes": [],
                            "checks": {"check1": None, "check2": None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 2,
                            },
                            "status": "PASS",
                        },
                        "requirement2": {
                            "name": "Requirement 2",
                            "description": "Description of requirement 2",
                            "attributes": [],
                            "checks": {},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 0,
                            },
                            "status": "PASS",
                        },
                    },
                    "requirements_status": {
                        "passed": 1,  # total_requirements - manual
                        "failed": 0,
                        "manual": 1,  # requirement2 has 0 checks
                    },
                    "total_requirements": 2,
                }
            }
        }

        assert template == expected_template
