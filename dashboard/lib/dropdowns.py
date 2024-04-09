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
                value=assesment_times[0],
                clearable=False,
                multi=False,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )


def create_date_dropdown_compliance(assesment_times: list) -> html.Div:
    """
    Dropdown to select the date of the last available scan for each account.
    Args:
        assesment_times (list): List of dates of the last available scan for each account.
    Returns:
        html.Div: Dropdown to select the date of the last available scan for each account.
    """
    return html.Div(
        [
            html.Label(
                "Assesment Date:", className="text-prowler-stone-900 font-bold text-sm"
            ),
            dcc.Dropdown(
                id="date-filter-analytics",
                options=[
                    {"label": account, "value": account} for account in assesment_times
                ],
                value=assesment_times[0],
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
                "Region / Location / Namespace :",
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


def create_region_dropdown_compliance(regions: list) -> html.Div:
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
                "Region / Location / Namespace :",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="region-filter-compliance",
                options=[{"label": region, "value": region} for region in regions],
                value=["All"],  # Initial selection is ALL
                clearable=False,
                multi=True,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )


def create_account_dropdown(accounts: list) -> html.Div:
    """
    Dropdown to select the account.
    Args:
        accounts (list): List of accounts.
    Returns:
        html.Div: Dropdown to select the account.
    """
    return html.Div(
        [
            html.Label(
                "Account / Subscription / Project / Cluster :",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="cloud-account-filter",
                options=[{"label": account, "value": account} for account in accounts],
                value=["All"],  # Initial selection is ALL
                clearable=False,
                multi=True,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )


def create_account_dropdown_compliance(accounts: list) -> html.Div:
    """
    Dropdown to select the account.
    Args:
        accounts (list): List of accounts.
    Returns:
        html.Div: Dropdown to select the account.
    """
    return html.Div(
        [
            html.Label(
                "Account / Subscription / Project / Cluster :",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="cloud-account-filter-compliance",
                options=[{"label": account, "value": account} for account in accounts],
                value=["All"],  # Initial selection is ALL
                clearable=False,
                multi=True,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )


def create_compliance_dropdown(compliance: list) -> html.Div:
    """
    Dropdown to select the compliance.
    Args:
        compliance (list): List of compliance.
    Returns:
        html.Div: Dropdown to select the compliance.
    """
    return html.Div(
        [
            html.Label(
                "Compliance:", className="text-prowler-stone-900 font-bold text-sm"
            ),
            dcc.Dropdown(
                id="report-compliance-filter",
                options=[{"label": i, "value": i} for i in compliance],
                value=compliance[0],
                clearable=False,
                style={"color": "#000000"},
            ),
        ],
    )


def create_severity_dropdown(severity: list) -> html.Div:
    """
    Dropdown to select the severity.
    Args:
        severity (list): List of severity.
    Returns:
        html.Div: Dropdown to select the severity.
    """
    return html.Div(
        [
            html.Label(
                "Severity:", className="text-prowler-stone-900 font-bold text-sm"
            ),
            dcc.Dropdown(
                id="severity-filter",
                options=[{"label": i, "value": i} for i in severity],
                value=["All"],
                clearable=False,
                multi=True,
                style={"color": "#000000"},
            ),
        ],
    )


def create_service_dropdown(services: list) -> html.Div:
    """
    Dropdown to select the service.
    Args:
        services (list): List of services.
    Returns:
        html.Div: Dropdown to select the service.
    """
    return html.Div(
        [
            html.Label(
                "Service:", className="text-prowler-stone-900 font-bold text-sm"
            ),
            dcc.Dropdown(
                id="service-filter",
                options=[{"label": i, "value": i} for i in services],
                value=["All"],
                clearable=False,
                multi=True,
                style={"color": "#000000"},
            ),
        ],
    )


def create_status_dropdown(status: list) -> html.Div:
    """
    Dropdown to select the status.
    Args:
        status (list): List of status.
    Returns:
        html.Div: Dropdown to select the status.
    """
    return html.Div(
        [
            html.Label("Status:", className="text-prowler-stone-900 font-bold text-sm"),
            dcc.Dropdown(
                id="status-filter",
                options=[{"label": i, "value": i} for i in status],
                value=["All"],
                clearable=False,
                multi=True,
                style={"color": "#000000"},
            ),
        ],
    )


def create_table_row_dropdown(table_rows: list) -> html.Div:
    """
    Dropdown to select the number of rows in the table.
    Args:
        table_rows (list): List of number of rows.
    Returns:
        html.Div: Dropdown to select the number of rows in the table.
    """
    return html.Div(
        [
            dcc.Dropdown(
                id="table-rows",
                options=[{"label": i, "value": i} for i in table_rows],
                value=table_rows[0],
                clearable=False,
                style={"color": "#000000", "margin-right": "10px"},
            ),
        ],
    )
