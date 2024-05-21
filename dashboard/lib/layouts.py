from dash import dcc, html


def create_layout_overview(
    account_dropdown: html.Div,
    date_dropdown: html.Div,
    region_dropdown: html.Div,
    download_button_csv: html.Button,
    download_button_xlsx: html.Button,
    severity_dropdown: html.Div,
    service_dropdown: html.Div,
    table_row_dropdown: html.Div,
    status_dropdown: html.Div,
    table_div_header: html.Div,
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
                className="grid gap-x-4 mt-[30px] mb-[30px] sm:grid-cols-2 lg:grid-cols-3",
            ),
            html.Div(
                [
                    html.Div([severity_dropdown], className=""),
                    html.Div([service_dropdown], className=""),
                    html.Div([status_dropdown], className=""),
                ],
                className="grid gap-x-4 mb-[30px] sm:grid-cols-2 lg:grid-cols-3",
            ),
            html.Div(
                [
                    html.Div(className="flex", id="aws_card", n_clicks=0),
                    html.Div(className="flex", id="azure_card", n_clicks=0),
                    html.Div(className="flex", id="gcp_card", n_clicks=0),
                    html.Div(className="flex", id="k8s_card", n_clicks=0),
                ],
                className="grid gap-x-4 mb-[30px] sm:grid-cols-2 lg:grid-cols-4",
            ),
            html.H4(
                "Count of Findings by severity",
                className="text-prowler-stone-900 text-lg font-bold mb-[30px]",
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
                className="grid gap-x-4 grid-cols-12 mb-[30px]",
            ),
            html.Div(
                [
                    html.H4(
                        "Top Findings by Severity",
                        className="text-prowler-stone-900 text-lg font-bold",
                    ),
                    html.Div(
                        [
                            (
                                html.Label(
                                    "Table Rows:",
                                    className="text-prowler-stone-900 font-bold text-sm",
                                    style={"margin-right": "10px"},
                                )
                            ),
                            table_row_dropdown,
                            download_button_csv,
                            download_button_xlsx,
                        ],
                        className="flex justify-between items-center",
                    ),
                    dcc.Download(id="download-data"),
                ],
                className="flex justify-between items-center",
            ),
            table_div_header,
            html.Div(id="table", className="grid"),
        ],
        className="grid gap-x-8 2xl:container mx-auto",
    )


def create_layout_compliance(
    account_dropdown: html.Div,
    date_dropdown: html.Div,
    region_dropdown: html.Div,
    compliance_dropdown: html.Div,
) -> html.Div:
    return html.Div(
        [
            dcc.Location(id="url", refresh=False),
            html.Div(
                [
                    html.H1(
                        "Compliance",
                        className="text-prowler-stone-900 text-2xxl font-bold",
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
                        className="flex flex-col col-span-12 md:col-span-2 gap-y-4",
                        id="",
                    ),
                ],
                className="grid gap-x-4 gap-y-4 grid-cols-12 lg:gap-y-0",
            ),
            html.H4(
                "Details compliance:",
                className="text-prowler-stone-900 text-lg font-bold",
            ),
            html.Div(className="flex flex-wrap", id="output"),
        ],
        className="grid gap-x-8 gap-y-8 2xl:container mx-auto",
    )
