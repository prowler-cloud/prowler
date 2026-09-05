import os
from functools import lru_cache

import pytest

from prowler.lib.check.compliance_models import load_compliance_framework_universal
from prowler.lib.check.utils import recover_checks_from_provider

COMPLIANCE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "prowler", "compliance")
)


def _compliance_jsons() -> list[str]:
    paths = []
    for root, _, files in os.walk(COMPLIANCE_DIR):
        paths.extend(os.path.join(root, f) for f in files if f.endswith(".json"))
    return sorted(paths)


@lru_cache
def _check_ids(provider: str) -> frozenset[str]:
    return frozenset(name for name, _ in recover_checks_from_provider(provider))


@pytest.mark.parametrize("json_path", _compliance_jsons(), ids=os.path.basename)
class TestComplianceCatalogIntegrity:
    def test_requirement_ids_are_unique(self, json_path):
        framework = load_compliance_framework_universal(json_path)
        assert framework is not None, f"Failed to load {json_path}"

        ids = [requirement.id for requirement in framework.requirements]
        duplicated = sorted({rid for rid in ids if ids.count(rid) > 1})
        assert not duplicated, f"Duplicated requirement ids: {duplicated}"

    def test_requirements_do_not_repeat_checks(self, json_path):
        framework = load_compliance_framework_universal(json_path)
        assert framework is not None, f"Failed to load {json_path}"

        repeated = sorted(
            {
                (requirement.id, provider, check)
                for requirement in framework.requirements
                for provider, checks in requirement.checks.items()
                for check in checks
                if checks.count(check) > 1
            }
        )
        assert not repeated, f"Checks listed twice in a requirement: {repeated}"

    def test_referenced_checks_exist_for_provider(self, json_path):
        framework = load_compliance_framework_universal(json_path)
        assert framework is not None, f"Failed to load {json_path}"

        unknown = sorted(
            {
                (provider, check)
                for requirement in framework.requirements
                for provider, checks in requirement.checks.items()
                for check in checks
                if check not in _check_ids(provider)
            }
        )
        assert not unknown, f"Checks that do not exist for their provider: {unknown}"
