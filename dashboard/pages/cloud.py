"""Prowler Cloud upsell (gated) informational pages.

These routes live inside the Local Dashboard but do NOT reproduce any Prowler
Cloud functionality. Each renders the same reusable upgrade template with a
feature-specific name, icon, description, benefit bullets and UTM-tagged CTA.
All copy in ``CLOUD_FEATURES`` is normative — do not change wording,
capitalization or punctuation without Product approval.
"""

import dash
from dash import html

# Shared subtitle used across every gated page header.
CLOUD_SUBTITLE = "Discover more ways to protect and operate your cloud."

# Base Prowler Cloud URL; the UTM content value identifies the feature.
CLOUD_CTA_BASE = (
    "https://cloud.prowler.com/?utm_source=prowler-local-dashboard&utm_content="
)

# Path to the recolorable checkmark mask used for benefit bullets.
CHECK_ICON = "/assets/images/icons/cloud/check.svg"


# Normative feature definitions. ``icon`` points to a local mask asset so no
# external requests are needed and the glyph recolors per context.
CLOUD_FEATURES = [
    {
        "slug": "lighthouse-ai",
        "route": "/cloud/lighthouse-ai",
        "nav_label": "Lighthouse AI",
        "page_title": "Lighthouse AI",
        "card_title": "Unlock Lighthouse AI",
        "description": (
            "Work with an AI security analyst that understands your cloud "
            "posture and helps turn risk into action."
        ),
        "benefits": [
            "Ask questions about your security posture in plain language",
            "Investigate findings with context from your connected providers",
            "Move from insight to remediation faster",
        ],
        "utm_content": "lighthouse-ai",
        "icon": "/assets/images/icons/cloud/lighthouse-ai.svg",
    },
    {
        "slug": "attack-paths",
        "route": "/cloud/attack-paths",
        "nav_label": "Attack Paths",
        "page_title": "Attack Paths",
        "card_title": "Unlock Attack Paths",
        "description": (
            "Visualize the paths an attacker could take through connected "
            "resources before risk becomes compromise."
        ),
        "benefits": [
            "See exploitable relationships across your AWS environment",
            "Focus remediation on the paths with the greatest impact",
            "Explore each scan as a point-in-time security graph",
        ],
        "utm_content": "attack-paths",
        "icon": "/assets/images/icons/cloud/attack-paths.svg",
    },
    {
        "slug": "findings",
        "route": "/cloud/findings",
        "nav_label": "Findings",
        "page_title": "Findings",
        "card_title": "Unlock Findings",
        "description": (
            "Filter, investigate, and prioritize security findings across "
            "providers and scans from one workspace."
        ),
        "benefits": [
            "Search and filter findings across all connected accounts",
            "Track status, severity, ownership, and remediation context",
            "Triage findings and share a consistent source of truth with your security team",
        ],
        "utm_content": "findings",
        "icon": "/assets/images/icons/cloud/findings.svg",
    },
    {
        "slug": "alerts",
        "route": "/cloud/alerts",
        "nav_label": "Alerts",
        "page_title": "Alerts",
        "card_title": "Unlock Alerts",
        "description": (
            "Create alert rules and stay informed when scan results reveal "
            "the risks your team cares about."
        ),
        "benefits": [
            "Define alerts around the findings that matter most",
            "Route security signals to the right responders",
            "Reduce the time between detection and action",
        ],
        "utm_content": "alerts",
        "icon": "/assets/images/icons/cloud/alerts.svg",
    },
    {
        "slug": "mutelist",
        "route": "/cloud/mutelist",
        "nav_label": "Mutelist",
        "page_title": "Mutelist",
        "card_title": "Unlock Mutelist",
        "description": (
            "Quiet expected findings, document accepted risk, and keep your "
            "team focused on actionable work."
        ),
        "benefits": [
            "Create reusable rules for known exceptions",
            "Keep muted findings available for audit and review",
            "Cut noise without losing security context",
        ],
        "utm_content": "mutelist",
        "icon": "/assets/images/icons/cloud/mutelist.svg",
    },
    {
        "slug": "integrations",
        "route": "/cloud/integrations",
        "nav_label": "Integrations",
        "page_title": "Integrations",
        "card_title": "Unlock Integrations",
        "description": (
            "Connect Prowler to your security workflow so findings and scan "
            "data reach the tools your team already uses."
        ),
        "benefits": [
            "Connect ticketing, notification, and cloud security services",
            "Automate the handoff from detection to response",
            "Keep teams aligned without manual exports",
        ],
        "utm_content": "integrations",
        "icon": "/assets/images/icons/cloud/integrations.svg",
    },
    {
        "slug": "organization",
        "route": "/cloud/organization",
        "nav_label": "Organization",
        "page_title": "Organization",
        "card_title": "Unlock Organization",
        "description": (
            "Manage users, roles, and invitations while organizing cloud "
            "security work across your team."
        ),
        "benefits": [
            "Invite teammates into a shared security workspace",
            "Control access with role-based permissions",
            "Coordinate security operations across accounts and teams",
        ],
        "utm_content": "organization",
        "icon": "/assets/images/icons/cloud/organization.svg",
    },
]

# Convenience lookup for the navigation builder in ``__main__``.
CLOUD_FEATURES_BY_SLUG = {feature["slug"]: feature for feature in CLOUD_FEATURES}


def _mask_style(icon_url):
    """Return the inline style that renders a recolorable mask icon."""
    return {
        "WebkitMaskImage": f"url({icon_url})",
        "maskImage": f"url({icon_url})",
    }


def _benefit_item(text):
    return html.Li(
        [
            html.Span(
                className="pc-ico pc-benefit-check",
                style=_mask_style(CHECK_ICON),
            ),
            html.Span(text),
        ],
        className="pc-benefit",
    )


def build_cloud_layout(feature):
    """Build the reusable gated informational page for a single feature."""
    cta_url = f"{CLOUD_CTA_BASE}{feature['utm_content']}"

    return html.Div(
        html.Div(
            [
                # Page header: title + Prowler Cloud badge + shared subtitle.
                html.Div(
                    [
                        html.Div(
                            [
                                html.H1(
                                    feature["page_title"],
                                    className="pc-page-title",
                                ),
                                html.Span("Prowler Cloud", className="pc-pill"),
                            ],
                            className="pc-page-title-row",
                        ),
                        html.P(CLOUD_SUBTITLE, className="pc-page-subtitle"),
                    ],
                    className="pc-page-header",
                ),
                # Centered upgrade card.
                html.Div(
                    [
                        html.Div(className="pc-card-glow"),
                        html.Div(
                            [
                                html.Div(
                                    html.Span(
                                        className="pc-ico",
                                        style=_mask_style(feature["icon"]),
                                    ),
                                    className="pc-feature-icon",
                                ),
                                html.Div(
                                    "Available in Prowler Cloud",
                                    className="pc-avail",
                                ),
                                html.H2(
                                    feature["card_title"],
                                    className="pc-card-title",
                                ),
                                html.P(
                                    feature["description"],
                                    className="pc-card-desc",
                                ),
                                html.Ul(
                                    [
                                        _benefit_item(benefit)
                                        for benefit in feature["benefits"]
                                    ],
                                    className="pc-benefits",
                                ),
                                html.A(
                                    "Upgrade to Prowler Cloud",
                                    href=cta_url,
                                    target="_blank",
                                    rel="noopener noreferrer",
                                    className="pc-cta",
                                ),
                            ],
                            className="pc-card-body",
                        ),
                    ],
                    className="pc-card",
                ),
            ],
            className="pc-page pc-font",
        ),
    )


# Register one page per gated feature. A distinct module key keeps each entry
# unique in Dash's page registry while sharing the same template.
for _feature in CLOUD_FEATURES:
    dash.register_page(
        f"cloud_{_feature['slug'].replace('-', '_')}",
        path=_feature["route"],
        name=_feature["nav_label"],
        title=f"Prowler Dashboard - {_feature['page_title']}",
        layout=build_cloud_layout(_feature),
    )
