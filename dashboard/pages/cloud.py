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
    "https://cloud.prowler.com/sign-up?utm_source=prowler-local-dashboard&utm_content="
)

# Path to the recolorable checkmark mask used for benefit bullets.
CHECK_ICON = "/assets/images/icons/cloud/check.svg"

# Prowler Cloud pricing page used by the "Compare editions" secondary link.
CLOUD_PRICING_URL = "https://prowler.com/pricing"

# Findings hand-off CTA. Shares the ``report-handoff`` campaign and ``oss``
# medium with the OSS HTML report CTA; ``utm_source`` identifies this entry
# point and ``intent`` expresses the user's goal. The URL is static: no
# assessment data (accounts, resources, findings, paths) is ever appended.
FINDINGS_HANDOFF_CTA_URL = (
    "https://cloud.prowler.com/sign-up"
    "?utm_source=prowler-local-dashboard&utm_medium=oss"
    "&utm_campaign=report-handoff&utm_content=findings&intent=import-findings"
)

# Same hand-off for the Compliance page; only ``utm_content`` differs.
COMPLIANCE_HANDOFF_CTA_URL = (
    "https://cloud.prowler.com/sign-up"
    "?utm_source=prowler-local-dashboard&utm_medium=oss"
    "&utm_campaign=report-handoff&utm_content=compliance&intent=import-findings"
)

# Shared hand-off copy (identical to the OSS HTML report CTA).
HANDOFF_TITLE = "Keep scanning locally. Bring your findings to Prowler Cloud."
HANDOFF_DESCRIPTION = (
    "Import your accompanying OCSF report to explore managed security workflows."
)
HANDOFF_CTA_LABEL = "Explore Prowler Cloud"
HANDOFF_SECONDARY_LABEL = "Compare editions"
HANDOFF_NOTE = "Nothing is uploaded automatically."

# What Prowler Cloud adds on top of the local compliance view, as documented in
# the Compliance, Cross-Provider Compliance and Cross-Provider Type Compliance
# tutorials. Keep these verifiable; do not add unreleased capabilities.
COMPLIANCE_HANDOFF_BENEFITS = [
    "Compliance Watchlist to pin the frameworks you track",
    "Cross-account and cross-provider roll-ups of a framework, with a per-provider breakdown",
    "Downloadable CSV and PDF compliance reports",
]


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
        # Findings is a voluntary hand-off, not an upsell: the dashboard keeps
        # showing findings from CSV, and this page explains how to bring the
        # OCSF report to Prowler Cloud. Copy is shared with the OSS HTML report.
        "slug": "findings",
        "route": "/cloud/findings",
        "nav_label": "Findings",
        "page_title": "Findings",
        "card_title": "Keep scanning locally. Bring your findings to Prowler Cloud.",
        "description": (
            "Import your accompanying OCSF report to explore managed security "
            "workflows."
        ),
        "benefits": [],
        "utm_content": "findings",
        "icon": "/assets/images/icons/cloud/findings.svg",
        "cta_label": "Explore Prowler Cloud",
        "cta_url": FINDINGS_HANDOFF_CTA_URL,
        "secondary_link": {"label": "Compare editions", "href": CLOUD_PRICING_URL},
        "note": "Nothing is uploaded automatically.",
        "steps": {
            "title": "How to bring your results",
            "items": [
                "Create or sign in to your Prowler Cloud account.",
                "In Prowler Cloud, open Scans \u2192 Import Findings.",
                "Select the accompanying .ocsf.json report and start the import.",
            ],
            "notes": [
                "This dashboard reads CSV files. Cloud import requires the OCSF "
                "JSON report, not the CSV or HTML report.",
                "If you did not generate an OCSF report, include json-ocsf in "
                "your output formats on your next scan.",
                "Import Findings is available to roles with the Manage Ingestions "
                "permission on an active Prowler Cloud subscription; each cloud "
                "account in the report counts as a provider.",
            ],
        },
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


def _handoff_links(cta_url):
    """Return the primary CTA and the "Compare editions" link for a hand-off."""
    return html.Div(
        [
            html.A(
                HANDOFF_CTA_LABEL,
                href=cta_url,
                target="_blank",
                rel="noopener noreferrer",
                className="pc-cta",
            ),
            html.A(
                HANDOFF_SECONDARY_LABEL,
                href=CLOUD_PRICING_URL,
                target="_blank",
                rel="noopener noreferrer",
                className="pc-link-secondary",
            ),
        ],
        className="pc-cta-row",
    )


def build_compliance_handoff_card():
    """Build the compact hand-off card shown at the end of the Compliance page.

    The local compliance view keeps working from CSV; this card only explains
    what Prowler Cloud adds for compliance reporting. Static links only: no
    upload control, no request, no assessment data in URLs.
    """
    return html.Div(
        [
            html.Div("Available in Prowler Cloud", className="pc-avail"),
            html.H2(HANDOFF_TITLE, className="pc-handoff-title"),
            html.P(HANDOFF_DESCRIPTION, className="pc-card-desc pc-handoff-desc"),
            html.Ul(
                [_benefit_item(benefit) for benefit in COMPLIANCE_HANDOFF_BENEFITS],
                className="pc-benefits pc-handoff-benefits",
            ),
            _handoff_links(COMPLIANCE_HANDOFF_CTA_URL),
            html.P(HANDOFF_NOTE, className="pc-note"),
        ],
        className="pc-handoff pc-font",
        role="complementary",
    )


def _steps_block(steps):
    """Build the optional secondary "how to" block rendered below the message.

    It is plain text and links only: no file selector, upload control or
    request is introduced, since the browser cannot read local report files.
    """
    return html.Div(
        [
            html.H3(steps["title"], className="pc-steps-title"),
            html.Ol(
                [html.Li(item) for item in steps["items"]],
                className="pc-steps-list",
            ),
            *[html.P(note, className="pc-steps-note") for note in steps["notes"]],
        ],
        className="pc-steps",
    )


def build_cloud_layout(feature):
    """Build the reusable gated informational page for a single feature.

    Features may override the CTA (``cta_label``/``cta_url``) and add an
    optional ``steps`` block, ``secondary_link`` and ``note``. Features that
    do not set them render exactly as before.
    """
    cta_url = feature.get("cta_url") or f"{CLOUD_CTA_BASE}{feature['utm_content']}"
    cta_label = feature.get("cta_label", "Upgrade to Prowler Cloud")
    steps = feature.get("steps")
    secondary_link = feature.get("secondary_link")
    note = feature.get("note")

    cta_links = [
        html.A(
            cta_label,
            href=cta_url,
            target="_blank",
            rel="noopener noreferrer",
            className="pc-cta",
        )
    ]
    if secondary_link:
        cta_links.append(
            html.A(
                secondary_link["label"],
                href=secondary_link["href"],
                target="_blank",
                rel="noopener noreferrer",
                className="pc-link-secondary",
            )
        )

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
                                *([_steps_block(steps)] if steps else []),
                                *(
                                    [html.Div(cta_links, className="pc-cta-row")]
                                    if secondary_link
                                    else cta_links
                                ),
                                *([html.P(note, className="pc-note")] if note else []),
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
