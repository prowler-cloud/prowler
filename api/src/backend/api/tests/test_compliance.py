from unittest.mock import MagicMock, patch

from api.compliance import (
    generate_compliance_overview_template,
    generate_scan_compliance,
    get_prowler_provider_checks,
    get_prowler_provider_compliance,
    load_prowler_checks,
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
            Tactics=["tactic1"],
            SubTechniques=["subtechnique1"],
            Platforms=["platform1"],
            TechniqueURL="https://example.com",
        )
        requirement2 = MagicMock(
            Id="requirement2",
            Name="Requirement 2",
            Description="Description of requirement 2",
            Attributes=[],
            Checks=[],
            Tactics=[],
            SubTechniques=[],
            Platforms=[],
            TechniqueURL="",
        )
        compliance1 = MagicMock(
            Requirements=[requirement1, requirement2],
            Framework="Framework 1",
            Version="1.0",
            Description="Description of compliance1",
            Name="Compliance 1",
        )
        prowler_compliance = {"aws": {"compliance1": compliance1}}

        template = generate_compliance_overview_template(prowler_compliance)

        expected_template = {
            "aws": {
                "compliance1": {
                    "framework": "Framework 1",
                    "name": "Compliance 1",
                    "version": "1.0",
                    "provider": "aws",
                    "description": "Description of compliance1",
                    "requirements": {
                        "requirement1": {
                            "name": "Requirement 1",
                            "description": "Description of requirement 1",
                            "tactics": ["tactic1"],
                            "subtechniques": ["subtechnique1"],
                            "platforms": ["platform1"],
                            "technique_url": "https://example.com",
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
                            "tactics": [],
                            "subtechniques": [],
                            "platforms": [],
                            "technique_url": "",
                            "attributes": [],
                            "checks": {},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 0,
                            },
                            "status": "MANUAL",
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
