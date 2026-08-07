# Importing Packages
import sys
import warnings

import click
import dash
import dash_bootstrap_components as dbc
from colorama import Fore, Style
from dash import dcc, html
from dash.dependencies import Input, Output

from dashboard.config import folder_path_overview
from prowler.config.config import orange_color
from prowler.lib.banner import print_banner

warnings.filterwarnings("ignore")

cli = sys.modules["flask.cli"]
print_banner()
print(
    f"{Fore.GREEN}Loading all CSV files from the folder {folder_path_overview} ...\n{Style.RESET_ALL}"
)
cli.show_server_banner = lambda *_: click.echo(
    f"{Fore.YELLOW}NOTE:{Style.RESET_ALL} If you are using {Fore.GREEN}{Style.BRIGHT}Prowler Cloud{Style.RESET_ALL} with the S3 integration or that integration \nfrom {Fore.CYAN}{Style.BRIGHT}Prowler CLI{Style.RESET_ALL} and you want to use your data from your S3 bucket,\nrun: `{orange_color}aws s3 cp s3://<your-bucket>/output/csv ./output --recursive{Style.RESET_ALL}`\nand then run `prowler dashboard` again to load the new files."
)

# Initialize the app - incorporate css
dashboard = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.FLATLY],
    use_pages=True,
    suppress_callback_exceptions=True,
    title="Prowler Dashboard",
)

# ``use_pages`` above already imported dashboard/pages/cloud.py and registered
# every /cloud/* route. Import its metadata now (after app instantiation) so
# the sidebar and the gated pages share a single source of truth.
from dashboard.pages.cloud import CLOUD_FEATURES_BY_SLUG  # noqa: E402

ICON_DIR = "/assets/images/icons/cloud"

# Official marketing "PROWLER / LOCAL DASHBOARD" lockup (white wordmark + teal
# gradient sublabel) shown in the expanded sidebar. Vector SVG so it stays crisp
# at any DPI. The sublabel is right-anchored (text-anchor="end"), so a font
# fallback widens it leftward rather than clipping at the edge.
prowler_lockup = html.Img(
    src=f"{ICON_DIR}/prowler-lockup.svg",
    alt="Prowler Local Dashboard",
    className="pc-brand-lockup",
)

# Compact brand mark shown only when the sidebar collapses to its icon rail.
prowler_mark = html.Img(
    src=f"{ICON_DIR}/prowler-mark.svg",
    alt="Prowler",
    className="pc-brand-mark",
)

# Locally functional destinations (Overview + Compliance).
DASHBOARD_ITEMS = [
    {"label": "Overview", "route": "/", "icon": f"{ICON_DIR}/overview.svg"},
    {
        "label": "Compliance",
        "route": "/compliance",
        "icon": f"{ICON_DIR}/compliance.svg",
    },
]

# Gated navigation groups reference the shared feature metadata by slug so the
# sidebar and the informational pages never drift apart.
GATED_GROUPS = [
    ("Upgrade to Prowler Cloud", ["lighthouse-ai", "attack-paths", "findings"]),
    ("Configuration", ["alerts", "mutelist", "integrations"]),
    ("Workspace", ["organization"]),
]

HELP_LINKS = [
    {
        "title": "Help",
        "url": "https://github.com/prowler-cloud/prowler/issues",
        "icon": f"{ICON_DIR}/help.svg",
    },
    {
        "title": "Docs",
        "url": "https://docs.prowler.com",
        "icon": f"{ICON_DIR}/docs.svg",
    },
]


def _mask_style(icon_url):
    """Inline style rendering a recolorable mask icon from a local asset."""
    return {
        "WebkitMaskImage": f"url({icon_url})",
        "maskImage": f"url({icon_url})",
    }


def _nav_icon(icon_url):
    return html.Span(className="pc-ico", style=_mask_style(icon_url))


def _nav_item(label, route, icon_url, current_path, gated=False):
    is_active = current_path == route
    class_name = "pc-nav-item pc-active" if is_active else "pc-nav-item"

    content = [
        _nav_icon(icon_url),
        html.Span(label, className="pc-nav-label"),
    ]
    if gated:
        content.append(html.Span("Prowler Cloud", className="pc-pill"))

    return dcc.Link(content, href=route, className=class_name)


def _section_label(title):
    return html.Div(title, className="pc-section")


def generate_sidebar(current_path):
    children = [
        # Brand lockup: full wordmark when expanded, compact mark when collapsed.
        html.Div(
            [prowler_lockup, prowler_mark],
            className="pc-brand",
        ),
        # Dashboards section — the only locally functional destinations.
        _section_label("Dashboards"),
        html.Nav(
            [
                _nav_item(item["label"], item["route"], item["icon"], current_path)
                for item in DASHBOARD_ITEMS
            ],
            className="pc-nav",
        ),
    ]

    # Gated groups (Prowler Cloud only).
    for section_title, slugs in GATED_GROUPS:
        children.append(_section_label(section_title))
        children.append(
            html.Nav(
                [
                    _nav_item(
                        CLOUD_FEATURES_BY_SLUG[slug]["nav_label"],
                        CLOUD_FEATURES_BY_SLUG[slug]["route"],
                        CLOUD_FEATURES_BY_SLUG[slug]["icon"],
                        current_path,
                        gated=True,
                    )
                    for slug in slugs
                ],
                className="pc-nav",
            )
        )

    # Help and Docs pinned to the bottom, separated by a neutral top border.
    children.append(
        html.Nav(
            [
                html.A(
                    [
                        _nav_icon(link["icon"]),
                        html.Span(link["title"], className="pc-nav-label"),
                    ],
                    href=link["url"],
                    target="_blank",
                    rel="noopener noreferrer",
                    className="pc-nav-item",
                )
                for link in HELP_LINKS
            ],
            className="pc-nav pc-footer",
        )
    )

    return html.Div(children, className="pc-sidebar pc-font")


# Layout
dashboard.layout = html.Div(
    [
        html.Link(rel="icon", href="assets/favicon.ico"),
        html.Div(
            [
                # Dynamic sidebar (rebuilt on navigation for active state).
                html.Div(id="navigation-bar"),
                # Main pane hosting the routed page content.
                html.Div(
                    html.Div(
                        dash.page_container,
                        className="pc-main-inner",
                    ),
                    id="content_select",
                    className="pc-main pc-font no-scrollbar",
                ),
            ],
            className="pc-shell",
        ),
    ],
    className="h-screen mx-auto",
)


# Callback to update navigation bar.
#
# Triggered off Dash Pages' own location (``_pages_location``) rather than a
# separate ``dcc.Location``. A standalone ``dcc.Location(id="url")`` stops
# emitting ``pathname`` when navigating between two pages that render an
# identical component tree — every ``/cloud/*`` gated page shares the same
# ``build_cloud_layout`` structure — which left the active highlight stuck on
# the first gated page visited. ``_pages_location`` fires on every route change.
@dashboard.callback(
    Output("navigation-bar", "children"), [Input("_pages_location", "pathname")]
)
def update_nav_bar(pathname):
    return generate_sidebar(pathname)
