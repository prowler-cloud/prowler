"""Prowler Cloud promo: sidebar hero + image-only product tour.

Drives CLI dashboard users toward Prowler Cloud. The sidebar shows a catchy,
on-brand hero card; clicking it opens a modal that walks through the real
Prowler Cloud experience using product screenshots.

The visual styling lives in ``dashboard/assets/cloud-promo.css`` (Dash loads
every CSS file under ``assets/`` automatically, so this does not depend on the
precompiled Tailwind bundle).
"""

from dash import dcc, html
from dash.dependencies import Input, Output, State

# Where every CTA points. Single source of truth so links stay consistent.
CLOUD_URL = "https://prowler.com/"

# Ordered product tour. Each slide is one real Prowler Cloud screenshot plus a
# short, benefit-led caption. The last slide carries the closing call to action.
TOUR_SLIDES = [
    {
        "image": "/assets/images/cloud/tour-1-overview.png",
        "eyebrow": "01 · Overview",
        "title": "Your whole cloud, one view",
        "text": (
            "Prowler ThreatScore, severity breakdown, resource inventory and "
            "attack surface — thousands of findings, prioritized at a glance."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-2-attack-paths.png",
        "eyebrow": "02 · Attack Paths",
        "title": "See the attack path before they do",
        "text": (
            "Visualize how attackers chain misconfigurations across roles, "
            "policies and identities to reach your crown jewels."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-3-lighthouse.png",
        "eyebrow": "03 · Lighthouse AI",
        "title": "Ask your cloud anything",
        "text": (
            "Lighthouse AI + MCP delivers autonomous triage, prioritization and "
            "remediation — risk answers in plain English, not spreadsheets."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-4-scans.png",
        "eyebrow": "04 · Continuous scanning",
        "title": "Scan every account, on a schedule",
        "text": (
            "Onboard whole organizations and scan all your AWS, Azure, GCP, "
            "M365 and Kubernetes accounts at once, with full history and trends."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-5-compliance.png",
        "eyebrow": "05 · Compliance",
        "title": "50+ frameworks, always live",
        "text": (
            "CIS, NIST, PCI DSS, ISO 27001, HIPAA, SOC 2, ENS and more — scored "
            "continuously with one-click evidence export."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-6-integrations.png",
        "eyebrow": "06 · Integrations",
        "title": "Plugs into your stack",
        "text": (
            "Jira, Slack, AWS Security Hub, Amazon S3, SAML SSO and RBAC — push "
            "findings where your team already works."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-7-alerts.png",
        "eyebrow": "07 · Alerts",
        "title": "Stay ahead with smart alerts",
        "text": (
            "Get notified the moment findings match your conditions — daily "
            "digests or real-time, routed to the people who need them."
        ),
    },
    {
        "image": "/assets/images/cloud/tour-8-import.png",
        "eyebrow": "From CLI to Cloud",
        "title": "Bring what you already have",
        "text": (
            "Already scanning with the Prowler CLI? Import your existing findings "
            "into Prowler Cloud in one click — no rescan, no lost history."
        ),
        "cta": "Start free on Prowler Cloud",
    },
]

# Component ids reused by the layout and the callbacks.
TRIGGER_ID = "cloud-promo-trigger"
CLOSE_ID = "cloud-tour-close"
BACKDROP_ID = "cloud-tour-backdrop"
PREV_ID = "cloud-tour-prev"
NEXT_ID = "cloud-tour-next"
OVERLAY_ID = "cloud-tour-overlay"
OPEN_STORE_ID = "cloud-tour-open"
INDEX_STORE_ID = "cloud-tour-index"

_OVERLAY_HIDDEN = {"display": "none"}
_OVERLAY_VISIBLE = {"display": "flex"}


def next_tour_state(trigger_id: str, is_open: bool, index: int, total: int):
    """Pure reducer for the tour modal.

    Returns the next ``(is_open, index)`` given which control fired. Kept free of
    Dash so the navigation logic is unit-testable in isolation.
    """
    if total <= 0:
        return False, 0
    if trigger_id == TRIGGER_ID:
        return True, 0
    if trigger_id in (CLOSE_ID, BACKDROP_ID):
        return False, index
    if trigger_id == NEXT_ID:
        return is_open, (index + 1) % total
    if trigger_id == PREV_ID:
        return is_open, (index - 1) % total
    return is_open, index


def cloud_promo_card() -> html.Div:
    """Catchy, on-brand sidebar hero. Click opens the product tour."""
    return html.Div(
        html.Div(
            [
                html.Span("Prowler Cloud", className="cloud-promo-eyebrow"),
                html.Span(
                    "Your cloud, continuously secured.",
                    className="cloud-promo-title",
                ),
                html.Span(
                    [
                        "See it in action",
                        html.Span("→", className="cloud-promo-arrow"),
                    ],
                    className="cloud-promo-cta",
                ),
            ],
            className="cloud-promo-card",
            id=TRIGGER_ID,
            n_clicks=0,
        ),
        className="cloud-promo-card-wrap",
    )


def _slide_dots(total: int) -> list:
    return [
        html.Span(className="cloud-tour-dot", id={"type": "cloud-tour-dot", "index": i})
        for i in range(total)
    ]


def cloud_tour_modal() -> html.Div:
    """Root-level modal that plays the image-only Prowler Cloud tour."""
    first = TOUR_SLIDES[0]
    total = len(TOUR_SLIDES)
    return html.Div(
        [
            dcc.Store(id=OPEN_STORE_ID, data=False),
            dcc.Store(id=INDEX_STORE_ID, data=0),
            html.Div(
                [
                    html.Div(
                        id=BACKDROP_ID, className="cloud-tour-backdrop", n_clicks=0
                    ),
                    html.Div(
                        [
                            html.Button(
                                "✕",
                                id=CLOSE_ID,
                                className="cloud-tour-close",
                                n_clicks=0,
                                **{"aria-label": "Close tour"},
                            ),
                            html.Div(
                                html.Img(
                                    id="cloud-tour-image",
                                    src=first["image"],
                                    className="cloud-tour-image",
                                    alt="Prowler Cloud product screenshot",
                                ),
                                className="cloud-tour-stage",
                            ),
                            html.Div(
                                [
                                    html.Span(
                                        first["eyebrow"],
                                        id="cloud-tour-eyebrow",
                                        className="cloud-tour-eyebrow",
                                    ),
                                    html.H3(
                                        first["title"],
                                        id="cloud-tour-title",
                                        className="cloud-tour-title",
                                    ),
                                    html.P(
                                        first["text"],
                                        id="cloud-tour-text",
                                        className="cloud-tour-text",
                                    ),
                                    html.A(
                                        first.get("cta", "Start free on Prowler Cloud"),
                                        id="cloud-tour-cta",
                                        href=CLOUD_URL,
                                        target="_blank",
                                        className="cloud-tour-cta",
                                        style={"display": "none"},
                                    ),
                                ],
                                className="cloud-tour-caption",
                            ),
                            html.Div(
                                [
                                    html.Button(
                                        "‹",
                                        id=PREV_ID,
                                        className="cloud-tour-nav",
                                        n_clicks=0,
                                        **{"aria-label": "Previous"},
                                    ),
                                    html.Div(
                                        _slide_dots(total),
                                        id="cloud-tour-dots",
                                        className="cloud-tour-dots",
                                    ),
                                    html.Button(
                                        "›",
                                        id=NEXT_ID,
                                        className="cloud-tour-nav",
                                        n_clicks=0,
                                        **{"aria-label": "Next"},
                                    ),
                                ],
                                className="cloud-tour-controls",
                            ),
                        ],
                        className="cloud-tour-dialog",
                    ),
                ],
                id=OVERLAY_ID,
                className="cloud-tour-overlay",
                style=_OVERLAY_HIDDEN,
            ),
        ]
    )


def register_cloud_promo_callbacks(app) -> None:
    """Wire the tour open/close/navigation into a Dash app."""

    @app.callback(
        Output(OPEN_STORE_ID, "data"),
        Output(INDEX_STORE_ID, "data"),
        Input(TRIGGER_ID, "n_clicks"),
        Input(CLOSE_ID, "n_clicks"),
        Input(BACKDROP_ID, "n_clicks"),
        Input(PREV_ID, "n_clicks"),
        Input(NEXT_ID, "n_clicks"),
        State(OPEN_STORE_ID, "data"),
        State(INDEX_STORE_ID, "data"),
        prevent_initial_call=True,
    )
    def _drive_tour(_t, _c, _b, _p, _n, is_open, index):
        from dash import ctx
        from dash.exceptions import PreventUpdate

        # The trigger button lives inside the dynamically rendered sidebar, so it
        # appears after the initial load. Ignore the spurious fire when a control
        # merely mounts (n_clicks 0/None) — only react to real clicks.
        if not ctx.triggered or not ctx.triggered[0]["value"]:
            raise PreventUpdate
        trigger_id = ctx.triggered_id
        return next_tour_state(
            trigger_id, bool(is_open), int(index or 0), len(TOUR_SLIDES)
        )

    @app.callback(
        Output(OVERLAY_ID, "style"),
        Output("cloud-tour-image", "src"),
        Output("cloud-tour-eyebrow", "children"),
        Output("cloud-tour-title", "children"),
        Output("cloud-tour-text", "children"),
        Output("cloud-tour-cta", "children"),
        Output("cloud-tour-cta", "style"),
        Output("cloud-tour-dots", "children"),
        Input(OPEN_STORE_ID, "data"),
        Input(INDEX_STORE_ID, "data"),
    )
    def _render_tour(is_open, index):
        index = int(index or 0) % len(TOUR_SLIDES)
        slide = TOUR_SLIDES[index]
        overlay_style = _OVERLAY_VISIBLE if is_open else _OVERLAY_HIDDEN
        cta_label = slide.get("cta")
        # Always occupy the CTA box (reserve space) so the dialog height stays
        # constant across slides; only its visibility changes.
        cta_style = {
            "display": "inline-flex",
            "visibility": "visible" if cta_label else "hidden",
        }
        dots = [
            html.Span(
                className=(
                    "cloud-tour-dot cloud-tour-dot--active"
                    if i == index
                    else "cloud-tour-dot"
                )
            )
            for i in range(len(TOUR_SLIDES))
        ]
        return (
            overlay_style,
            slide["image"],
            slide["eyebrow"],
            slide["title"],
            slide["text"],
            cta_label or "Start free on Prowler Cloud",
            cta_style,
            dots,
        )
