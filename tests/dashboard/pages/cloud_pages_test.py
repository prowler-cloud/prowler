import json

import pytest
from dash import html
from plotly.utils import PlotlyJSONEncoder

from dashboard.pages.cloud import (
    CLOUD_CTA_BASE,
    CLOUD_FEATURES,
    CLOUD_FEATURES_BY_SLUG,
    CLOUD_PRICING_URL,
    FINDINGS_HANDOFF_CTA_URL,
    build_cloud_layout,
)

EXPECTED_FINDINGS_CTA_URL = (
    "https://cloud.prowler.com/sign-up?utm_source=prowler-local-dashboard"
    "&utm_medium=oss&utm_campaign=report-handoff&utm_content=findings"
    "&intent=import-findings"
)


def _serialize(component) -> str:
    """Flatten a Dash component tree into a JSON string for text assertions."""
    return json.dumps(component, cls=PlotlyJSONEncoder, ensure_ascii=False)


def _links(component):
    """Yield every ``html.A`` component in the tree."""
    stack = [component]
    while stack:
        node = stack.pop()
        if isinstance(node, html.A):
            yield node
        children = getattr(node, "children", None)
        if isinstance(children, (list, tuple)):
            # Reverse so the stack yields children in document order
            stack.extend(reversed(children))
        elif children is not None and hasattr(children, "to_plotly_json"):
            stack.append(children)


class TestFindingsHandoffPage:
    def setup_method(self):
        self.layout = build_cloud_layout(CLOUD_FEATURES_BY_SLUG["findings"])
        self.text = _serialize(self.layout)

    def test_shared_message_matches_html_report_cta(self):
        assert (
            "Keep scanning locally. Bring your findings to Prowler Cloud." in self.text
        )
        assert (
            "Import your accompanying OCSF report to explore managed security workflows."
            in self.text
        )
        assert "Explore Prowler Cloud" in self.text
        assert "Compare editions" in self.text
        assert "Nothing is uploaded automatically." in self.text

    def test_old_upsell_copy_is_gone(self):
        assert "Unlock Findings" not in self.text
        assert "Upgrade to Prowler Cloud" not in self.text
        assert (
            "Search and filter findings across all connected accounts" not in self.text
        )

    def test_cta_keeps_every_tracking_parameter(self):
        cta = next(a for a in _links(self.layout) if a.className == "pc-cta")
        assert cta.href == EXPECTED_FINDINGS_CTA_URL == FINDINGS_HANDOFF_CTA_URL
        assert cta.children == "Explore Prowler Cloud"
        assert cta.target == "_blank"
        assert cta.rel == "noopener noreferrer"
        for param in (
            "utm_source=prowler-local-dashboard",
            "utm_medium=oss",
            "utm_campaign=report-handoff",
            "utm_content=findings",
            "intent=import-findings",
        ):
            assert param in cta.href

    def test_secondary_link_points_to_pricing(self):
        link = next(
            a for a in _links(self.layout) if a.className == "pc-link-secondary"
        )
        assert link.href == CLOUD_PRICING_URL == "https://prowler.com/pricing"
        assert link.children == "Compare editions"
        assert link.target == "_blank"
        assert link.rel == "noopener noreferrer"

    def test_steps_block_content(self):
        assert "How to bring your results" in self.text
        assert "Create or sign in to your Prowler Cloud account." in self.text
        assert "In Prowler Cloud, open Scans → Import Findings." in self.text
        assert (
            "Select the accompanying .ocsf.json report and start the import."
            in self.text
        )
        assert (
            "This dashboard reads CSV files. Cloud import requires the OCSF JSON report, not the CSV or HTML report."
            in self.text
        )
        assert (
            "If you did not generate an OCSF report, include json-ocsf in your output formats on your next scan."
            in self.text
        )
        assert "Manage Ingestions" in self.text

    def test_hierarchy_message_steps_cta_note(self):
        assert (
            self.text.index("Keep scanning locally.")
            < self.text.index("How to bring your results")
            < self.text.index("Explore Prowler Cloud")
            < self.text.index("Nothing is uploaded automatically.")
        )

    def test_no_upload_or_file_selector(self):
        assert "Upload" not in self.text
        assert '"type": "Input"' not in self.text
        assert "<input" not in self.text.lower()

    def test_all_external_links_open_safely(self):
        links = list(_links(self.layout))
        assert len(links) == 2
        for link in links:
            assert link.href.startswith("https://")
            assert link.rel == "noopener noreferrer"

    def test_no_assessment_data_in_urls(self):
        for link in _links(self.layout):
            assert "/Users/" not in link.href
            assert "account" not in link.href.lower()
            assert ".csv" not in link.href


class TestOtherCloudPagesUnchanged:
    @pytest.mark.parametrize(
        "slug",
        [f["slug"] for f in CLOUD_FEATURES if f["slug"] not in ("findings", "mcp")],
    )
    def test_other_pages_keep_upsell_template(self, slug):
        feature = CLOUD_FEATURES_BY_SLUG[slug]
        layout = build_cloud_layout(feature)
        text = _serialize(layout)
        links = list(_links(layout))

        assert feature["card_title"].startswith("Unlock ")
        assert feature["card_title"] in text
        assert len(links) == 1
        assert links[0].children == "Upgrade to Prowler Cloud"
        assert links[0].href == f"{CLOUD_CTA_BASE}{feature['utm_content']}"
        assert len(feature["benefits"]) == 3
        assert "How to bring your results" not in text
        assert "pc-steps" not in text
        assert "pc-note" not in text
        assert "pc-link-secondary" not in text
        assert "report-handoff" not in text

    def test_navigation_label_unchanged(self):
        assert CLOUD_FEATURES_BY_SLUG["findings"]["nav_label"] == "Findings"
        assert CLOUD_FEATURES_BY_SLUG["findings"]["route"] == "/cloud/findings"


class TestComplianceHandoffCard:
    def setup_method(self):
        from dashboard.pages.cloud import (
            COMPLIANCE_HANDOFF_CTA_URL,
            build_compliance_handoff_card,
        )

        self.expected_url = COMPLIANCE_HANDOFF_CTA_URL
        self.card = build_compliance_handoff_card()
        self.text = _serialize(self.card)

    def test_shared_message_and_note(self):
        assert (
            "Keep scanning locally. Bring your findings to Prowler Cloud." in self.text
        )
        assert (
            "Import your accompanying OCSF report to explore managed security workflows."
            in self.text
        )
        assert "Nothing is uploaded automatically." in self.text
        assert "Unlock" not in self.text

    def test_compliance_benefits_are_the_documented_ones(self):
        assert "Compliance Watchlist" in self.text
        assert "Cross-account and cross-provider roll-ups" in self.text
        assert "CSV and PDF compliance reports" in self.text
        assert "attack path" not in self.text.lower()
        assert "trial" not in self.text.lower()

    def test_links(self):
        links = list(_links(self.card))
        assert [a.children for a in links] == [
            "Explore Prowler Cloud",
            "Compare editions",
        ]
        cta, pricing = links
        assert (
            cta.href
            == self.expected_url
            == (
                "https://cloud.prowler.com/sign-up?utm_source=prowler-local-dashboard"
                "&utm_medium=oss&utm_campaign=report-handoff&utm_content=compliance"
                "&intent=import-findings"
            )
        )
        assert pricing.href == "https://prowler.com/pricing"
        for link in links:
            assert link.target == "_blank"
            assert link.rel == "noopener noreferrer"

    def test_no_upload_controls(self):
        assert "Upload" not in self.text
        assert '"type": "Input"' not in self.text


class TestComplianceLayoutIncludesHandoff:
    def test_card_is_last_element_and_header_link_kept(self):
        from dash import html

        from dashboard.lib.layouts import create_layout_compliance

        layout = create_layout_compliance(
            html.Div(id="a"), html.Div(id="d"), html.Div(id="r"), html.Div(id="c")
        )
        last = layout.children[-1]
        assert "pc-handoff" in last.className
        text = _serialize(layout)
        assert text.count("Keep scanning locally.") == 1
        # Existing header link and compliance containers are untouched
        assert "Subscribe to Prowler Cloud" in text
        assert '"id": "output"' in text
        assert '"id": "overall_status_result_graph"' in text


class TestMcpPage:
    def setup_method(self):
        self.feature = CLOUD_FEATURES_BY_SLUG["mcp"]
        self.layout = build_cloud_layout(self.feature)
        self.text = _serialize(self.layout)

    def test_copy_and_template(self):
        assert self.feature["nav_label"] == "MCP Server"
        assert self.feature["route"] == "/cloud/mcp"
        assert "Unlock Prowler MCP" in self.text
        assert "mcp.prowler.com" in self.text
        assert "Prowler MCP Server is currently a preview feature." in self.text
        assert len(self.feature["benefits"]) == 3
        assert "How to bring your results" not in self.text

    def test_links(self):
        links = list(_links(self.layout))
        assert [a.children for a in links] == [
            "Upgrade to Prowler Cloud",
            "Connect your AI agent",
        ]
        assert links[0].href == f"{CLOUD_CTA_BASE}mcp"
        assert links[1].href == "https://docs.prowler.com/user-guide/ai-agents/"
        for link in links:
            assert link.target == "_blank"
            assert link.rel == "noopener noreferrer"

    def test_icon_asset_exists(self):
        from pathlib import Path

        icon = Path("dashboard") / self.feature["icon"].lstrip("/")
        assert icon.is_file()


class TestPageTitles:
    def test_cloud_pages_are_titled_prowler_local_dashboard(self):
        import dash

        for feature in CLOUD_FEATURES:
            page = dash.page_registry[f"cloud_{feature['slug'].replace('-', '_')}"]
            assert page["title"] == f"Prowler Local Dashboard - {feature['page_title']}"
