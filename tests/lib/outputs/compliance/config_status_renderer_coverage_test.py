"""Guard that every dedicated compliance renderer applies the config-status rule.

Declaring ``ConfigRequirements`` in a framework JSON is inert unless the renderer
that builds its output actually evaluates them. A requirement whose configurable
checks ran with a config too loose to trust must be forced to FAIL; that override
lives in ``prowler.lib.check.compliance_config_eval`` and every renderer that
emits a finding's status (CSV transform, CLI table, OCSF) must route through it.

This test statically asserts the invariant: any renderer that reads a finding's
raw ``status`` must also reference one of the config-status helpers. It mirrors
the manual audit that caught ``okta_idaas_stig`` shipping ConfigRequirements that
its CSV and table renderers never applied, so the gap cannot silently reopen.
"""

import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
_RENDERER_DIR = _REPO_ROOT / "prowler" / "lib" / "outputs" / "compliance"

# Base/dispatch modules that orchestrate renderers but never emit a status row.
_EXCLUDED_BASENAMES = {
    "__init__.py",
    "models.py",
    "compliance.py",
    "compliance_check.py",
    "compliance_output.py",
}

# Any one of these, present in the source, means the renderer wires the override.
_CONFIG_STATUS_HELPERS = (
    "apply_config_status",
    "build_requirement_config_status",
    "resolve_requirement_config_status",
    "get_effective_status",
)

# A renderer builds its output from the finding's raw status via one of these.
_RAW_STATUS_MARKERS = ("finding.status", "finding.status_extended")


def _renderer_sources():
    for path in sorted(_RENDERER_DIR.glob("**/*.py")):
        if path.name in _EXCLUDED_BASENAMES or "__pycache__" in path.parts:
            continue
        yield path


@pytest.mark.parametrize(
    "renderer_path",
    [
        pytest.param(p, id=str(p.relative_to(_RENDERER_DIR)))
        for p in _renderer_sources()
    ],
)
def test_renderer_emitting_status_applies_config_status(renderer_path):
    source = renderer_path.read_text(encoding="utf-8")

    uses_raw_status = any(marker in source for marker in _RAW_STATUS_MARKERS)
    if not uses_raw_status:
        pytest.skip("renderer does not emit a finding's raw status")

    applies_config_status = any(helper in source for helper in _CONFIG_STATUS_HELPERS)
    assert applies_config_status, (
        f"{renderer_path.relative_to(_REPO_ROOT)} emits a finding's raw status but "
        "never applies the config-status override. Route it through "
        "apply_config_status / build_requirement_config_status (CSV/OCSF) or "
        "resolve_requirement_config_status / get_effective_status (CLI table), "
        "otherwise its ConfigRequirements are silently ignored."
    )
