from dash import dcc, html


def create_date_dropdown(assesment_times: list) -> html.Div:
    """
    Dropdown to select the date of the last available scan for each account.
    Args:
        assesment_times (list): List of dates of the last available scan for each account.
    Returns:
        html.Div: Dropdown to select the date of the last available scan for each account.
    """
    return html.Div(
        [
            html.Div(
                [
                    html.Label(
                        "Assessment date (last available scan) ",
                        className="text-prowler-stone-900 font-bold text-sm",
                    ),
                    html.Img(
                        id="info-file-over",
                        src="/assets/images/icons/help-black.png",
                        className="w-5",
                        title="The date of the last available scan for each account is displayed here. If you have not run prowler yet, the date will be empty.",
                    ),
                ],
                style={"display": "inline-flex"},
            ),
            dcc.Dropdown(
                id="report-date-filter",
                options=[
                    {"label": account, "value": account} for account in assesment_times
                ],
                value=assesment_times[0],  # Initial selection is ALL
                clearable=False,
                multi=False,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )


def create_region_dropdown(regions: list) -> html.Div:
    """
    Dropdown to select the region of the account.
    Args:
        regions (list): List of regions of the account.
    Returns:
        html.Div: Dropdown to select the region of the account.
    """
    return html.Div(
        [
            html.Label(
                "Region:",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="region-filter",
                options=[{"label": region, "value": region} for region in regions],
                value=["All"],  # Initial selection is ALL
                clearable=False,
                multi=True,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )
