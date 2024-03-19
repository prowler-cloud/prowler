from dash import dcc, html


def create_layout_overview(
    account_dropdown: html.Div, date_dropdown: html.Div, region_dropdown: html.Div
) -> html.Div:
    """
    Create the layout of the dashboard.
    Args:
        account_dropdown (html.Div): Dropdown to select the account.
        date_dropdown (html.Div): Dropdown to select the date of the last available scan for each account.
        region_dropdown (html.Div): Dropdown to select the region of the account.
    Returns:
        html.Div: Layout of the dashboard.
    """
    return html.Div(
        [
            dcc.Location(id="url", refresh=False),
            html.Div(
                [
                    html.H1(
                        "Scan Overview",
                        className="text-prowler-stone-900 text-2xxl font-bold",
                    ),
                    html.Div(className="d-flex flex-wrap", id="subscribe_card"),
                ],
                className="flex justify-between border-b border-prowler-500 pb-3",
            ),
            html.Div(
                [
                    html.Div([date_dropdown], className=""),
                    html.Div([account_dropdown], className=""),
                    html.Div([region_dropdown], className=""),
                ],
                className="grid gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-3 lg:gap-y-0",
            ),
            html.Div(
                [
                    html.Div(className="flex", id="aws_card"),
                    html.Div(className="flex", id="azure_card"),
                    html.Div(className="flex", id="gcp_card"),
                    html.Div(className="flex", id="k8s_card"),
                ],
                className="grid gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-4 lg:gap-y-0",
            ),
            html.H4(
                "Count of Failed Findings by severity",
                className="text-prowler-stone-900 text-lg font-bold",
            ),
            html.Div(
                [
                    html.Div(
                        className="flex flex-col col-span-12 sm:col-span-6 lg:col-span-3 gap-y-4",
                        id="status_graph",
                    ),
                    html.Div(
                        className="flex flex-col col-span-12 sm:col-span-6 lg:col-span-3 gap-y-4",
                        id="two_pie_chart",
                    ),
                    html.Div(
                        className="flex flex-col col-span-12 sm:col-span-6 lg:col-span-6 col-end-13 gap-y-4",
                        id="line_plot",
                    ),
                ],
                className="grid gap-x-4 gap-y-4 grid-cols-12 lg:gap-y-0",
            ),
            html.Div(
                [
                    html.H4(
                        "Top 25 Failed Findings by Severity",
                        className="text-prowler-stone-900 text-lg font-bold",
                    ),
                    html.Button(
                        "Download this table as CSV",
                        id="download_link",
                        n_clicks=0,
                        className="border-solid border-2 border-prowler-stone-900/10 hover:border-solid hover:border-2 hover:border-prowler-stone-900/10 text-prowler-stone-900 inline-block px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 flex justify-end w-fit",
                    ),
                    dcc.Download(id="download-data"),
                ],
                className="flex justify-between items-center",
            ),
            html.Div(id="table", className="grid"),
        ],
        className="grid gap-x-8 gap-y-8 2xl:container mx-auto",
    )

def create_layout_compliance(account_dropdown: html.Div, date_dropdown: html.Div, region_dropdown: html.Div, compliance_dropdown: html.Div) -> html.Div:
    return html.Div(
        [
            dcc.Location(id="url", refresh=False),
            html.Div(
                [
                    html.H1(
                        "Compliance", className="text-prowler-stone-900 text-2xxl font-bold"
                    ),
                    html.A(
                        [
                            html.Img(src="assets/favicon.ico", className="w-5 mr-3"),
                            html.Span("Subscribe to prowler SaaS"),
                        ],
                        href="https://prowler.pro/",
                        target="_blank",
                        className="text-prowler-stone-900 inline-flex px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 border-solid border-1 hover:border-prowler-stone-900/10 hover:border-solid hover:border-1 border-prowler-stone-900/10",
                    ),
                ],
                className="flex justify-between border-b border-prowler-500 pb-3",
            ),
            html.Div(
                [
                    html.Div([date_dropdown], className=""),
                    html.Div([account_dropdown], className=""),
                    html.Div([region_dropdown], className=""),
                    html.Div([compliance_dropdown], className=""),
                ],
                className="grid gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-4 lg:gap-y-0",
            ),
            html.Div(
                [
                    html.Div(
                        className="flex flex-col col-span-12 md:col-span-4 gap-y-4",
                        id="overall_status_result_graph",
                    ),
                    html.Div(
                        className="flex flex-col col-span-12 md:col-span-7 md:col-end-13 gap-y-4",
                        id="security_level_graph",
                    ),
                    html.Div(
                        className="flex flex-col col-span-12 md:col-span-2 gap-y-4", id=""
                    ),
                ],
                className="grid gap-x-4 gap-y-4 grid-cols-12 lg:gap-y-0",
            ),
            html.H4(
                "Details compliance:", className="text-prowler-stone-900 text-lg font-bold"
            ),
            html.Div(className="flex flex-wrap", id="output"),
        ],
        className="grid gap-x-8 gap-y-8 2xl:container mx-auto",
    )