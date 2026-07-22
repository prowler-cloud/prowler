import json
from pathlib import Path

from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute_AssessmentStatus,
    CIS_Requirement_Attribute_Profile,
    Compliance,
)

PROWLER_ROOT = Path(__file__).parents[5] / "prowler"
FRAMEWORK_PATH = PROWLER_ROOT / "compliance" / "m365" / "cis_7.0_m365.json"
M365_SERVICES_PATH = PROWLER_ROOT / "providers" / "m365" / "services"

VALID_PROFILES = {p.value for p in CIS_Requirement_Attribute_Profile}
VALID_STATUSES = {s.value for s in CIS_Requirement_Attribute_AssessmentStatus}


def _existing_m365_checks() -> set:
    return {
        metadata.stem.replace(".metadata", "")
        for metadata in M365_SERVICES_PATH.rglob("*.metadata.json")
    }


class TestCIS7_0_M365:
    def test_framework_is_discoverable(self):
        frameworks = Compliance.get_bulk("m365")
        assert "cis_7.0_m365" in frameworks

    def test_framework_metadata(self):
        framework = Compliance.get_bulk("m365")["cis_7.0_m365"]
        assert framework.Framework == "CIS"
        assert framework.Provider == "M365"
        assert framework.Version == "7.0"
        assert framework.Name == "CIS Microsoft 365 Foundations Benchmark v7.0.0"
        assert len(framework.Requirements) == 160

    def test_requirement_ids_are_unique(self):
        framework = Compliance.get_bulk("m365")["cis_7.0_m365"]
        ids = [req.Id for req in framework.Requirements]
        assert len(ids) == len(set(ids))

    def test_each_requirement_has_one_attribute_with_section(self):
        framework = Compliance.get_bulk("m365")["cis_7.0_m365"]
        for req in framework.Requirements:
            assert len(req.Attributes) == 1, f"{req.Id} must have exactly one attribute"
            attribute = req.Attributes[0]
            assert attribute.Section, f"{req.Id} has an empty Section"
            assert attribute.Profile in VALID_PROFILES
            assert attribute.AssessmentStatus in VALID_STATUSES

    def test_all_mapped_checks_exist(self):
        # Every check referenced by the framework must resolve to a real M365 check,
        # otherwise the requirement would never be evaluated.
        existing = _existing_m365_checks()
        framework = json.loads(FRAMEWORK_PATH.read_text())
        unknown = {
            check
            for req in framework["Requirements"]
            for check in req["Checks"]
            if check not in existing
        }
        assert (
            not unknown
        ), f"Framework references unknown M365 checks: {sorted(unknown)}"
