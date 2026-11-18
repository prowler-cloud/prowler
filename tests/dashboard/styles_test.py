"""The dashboard styles apply with and without Dash's dev tools."""

import re
from pathlib import Path

import pytest

DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"
SOURCE_STYLESHEET = DASHBOARD_DIR / "src" / "input.css"
COMPILED_STYLESHEET = DASHBOARD_DIR / "assets" / "styles" / "dist" / "output.css"


@pytest.mark.parametrize(
    "stylesheet", [SOURCE_STYLESHEET, COMPILED_STYLESHEET], ids=lambda path: path.name
)
def test_styles_do_not_depend_on_the_dev_tools_wrapper(stylesheet):
    # Dash renders #_dash-app-content only as part of its dev tools UI, so a rule
    # anchored on it is lost when the dashboard runs without them.
    assert "_dash-app-content" not in stylesheet.read_text(encoding="utf-8")


def test_expanded_accordion_panels_stay_visible():
    css = COMPILED_STYLESHEET.read_text(encoding="utf-8")
    # Tailwind's `collapse` utility shares its class name with Bootstrap's accordion
    # panels, so the compiled stylesheet has to make the panels visible again.
    assert re.search(r"(?m)^\.collapse\s*\{\s*visibility:\s*collapse;?\s*\}", css)
    assert re.search(
        r"#react-entry-point \.accordion \.accordion-collapse\.collapse\s*\{"
        r"\s*visibility:\s*visible;?\s*\}",
        css,
    )
