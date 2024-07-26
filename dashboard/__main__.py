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
cli.show_server_banner = lambda *x: click.echo(
    f"{Fore.YELLOW}NOTE:{Style.RESET_ALL} If you are using {Fore.GREEN}{Style.BRIGHT}Prowler SaaS{Style.RESET_ALL} with the S3 integration or that integration \nfrom {Fore.CYAN}{Style.BRIGHT}Prowler Open Source{Style.RESET_ALL} and you want to use your data from your S3 bucket,\nrun: `{orange_color}aws s3 cp s3://<your-bucket>/output/csv ./output --recursive{Style.RESET_ALL}`\nand then run `prowler dashboard` again to load the new files."
)

# Initialize the app - incorporate css
dashboard = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.FLATLY],
    use_pages=True,
    suppress_callback_exceptions=True,
    title="Prowler Dashboard",
)

# Logo
prowler_logo = html.Img(
    src="https://prowler.com/wp-content/uploads/logo-dashboard.png", alt="Prowler Logo"
)

menu_icons = {
    "overview": "/assets/images/icons/overview.svg",
    "compliance": "/assets/images/icons/compliance.svg",
}


# Function to generate navigation links
def generate_nav_links(current_path):
    nav_links = []
    for page in dash.page_registry.values():
        # Gets the icon URL based on the page name
        icon_url = menu_icons.get(page["name"].lower())
        is_active = (
            " bg-prowler-stone-950 border-r-4 border-solid border-prowler-lime"
            if current_path == page["relative_path"]
            else ""
        )
        link_class = f"block hover:bg-prowler-stone-950 hover:border-r-4 hover:border-solid hover:border-prowler-lime{is_active}"

        link_content = html.Span(
            [
                html.Img(src=icon_url, className="w-5"),
                html.Span(
                    page["name"], className="font-medium text-base leading-6 text-white"
                ),
            ],
            className="flex justify-center lg:justify-normal items-center gap-x-3 py-2 px-3",
        )

        nav_link = html.Li(
            dcc.Link(link_content, href=page["relative_path"], className=link_class)
        )
        nav_links.append(nav_link)
    return nav_links


def generate_help_menu():
    help_links = [
        {
            "title": "Help",
            "url": "https://github.com/prowler-cloud/prowler/issues",
            "icon": "/assets/images/icons/help.png",
        },
        {
            "title": "Docs",
            "url": "https://docs.prowler.com",
            "icon": "/assets/images/icons/docs.png",
        },
    ]

    link_class = "block hover:bg-prowler-stone-950 hover:border-r-4 hover:border-solid hover:border-prowler-lime"

    menu_items = []
    for link in help_links:
        menu_item = html.Li(
            html.A(
                html.Span(
                    [
                        html.Img(src=link["icon"], className="w-5"),
                        html.Span(
                            link["title"],
                            className="font-medium text-base leading-6 text-white",
                        ),
                    ],
                    className="flex items-center gap-x-3 py-2 px-3",
                ),
                href=link["url"],
                target="_blank",
                className=link_class,
            )
        )
        menu_items.append(menu_item)

    return menu_items


# Layout
dashboard.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        html.Link(rel="icon", href="assets/favicon.ico"),
        # Placeholder for dynamic navigation bar
        html.Div(
            [
                html.Div(
                    id="navigation-bar", className="bg-prowler-stone-900 min-w-36 z-10"
                ),
                html.Div(
                    [
                        dash.page_container,
                    ],
                    id="content_select",
                    className="bg-prowler-white w-full col-span-11 h-screen mx-auto overflow-y-scroll no-scrollbar px-10 py-7",
                ),
            ],
            className="grid custom-grid 2xl:custom-grid-large h-screen",
        ),
    ],
    className="h-screen mx-auto",
)


# Callback to update navigation bar
@dashboard.callback(Output("navigation-bar", "children"), [Input("url", "pathname")])
def update_nav_bar(pathname):
    return html.Div(
        [
            html.Div([prowler_logo], className="mb-8 px-3"),
            html.H6(
                "Dashboards",
                className="px-3 text-prowler-stone-500 text-sm opacity-90 font-regular mb-2",
            ),
            html.Nav(
                [html.Ul(generate_nav_links(pathname), className="")],
                className="flex flex-col gap-y-6",
            ),
            html.Nav(
                [
                    html.A(
                        [
                            html.Span(
                                [
                                    html.Img(src="assets/favicon.ico", className="w-5"),
                                    "Subscribe to prowler SaaS",
                                ],
                                className="flex items-center gap-x-3 text-white",
                            ),
                        ],
                        href="https://prowler.com/",
                        target="_blank",
                        className="block p-3 uppercase text-xs hover:bg-prowler-stone-950 hover:border-r-4 hover:border-solid hover:border-prowler-lime",
                    ),
                    html.Ul(generate_help_menu(), className=""),
                ],
                className="flex flex-col gap-y-6 mt-auto",
            ),
        ],
        className="flex flex-col bg-prowler-stone-900 py-7 h-full",
    )
