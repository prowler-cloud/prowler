# Standard library imports
import glob
import json
import os
import warnings
from datetime import datetime, timedelta
from itertools import product

# Third-party imports
import dash
import dash_bootstrap_components as dbc
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import callback, callback_context, ctx, dcc, html
from dash.dependencies import Input, Output

# Config import
from dashboard.config import (
    critical_color,
    fail_color,
    folder_path_overview,
    high_color,
    info_color,
    informational_color,
    low_color,
    manual_color,
    medium_color,
    muted_fail_color,
    muted_manual_color,
    muted_pass_color,
    pass_color,
)
from dashboard.lib.cards import create_provider_card
from dashboard.lib.dropdowns import (
    create_account_dropdown,
    create_category_dropdown,
    create_date_dropdown,
    create_provider_dropdown,
    create_region_dropdown,
    create_service_dropdown,
    create_severity_dropdown,
    create_status_dropdown,
    create_table_row_dropdown,
)
from dashboard.lib.layouts import create_layout_overview
from prowler.lib.logger import logger

# Suppress warnings
warnings.filterwarnings("ignore")

# Global variables
# TODO: Create a flag to let the user put a custom path
csv_files = []

for file in glob.glob(os.path.join(folder_path_overview, "*.csv")):
    try:
        df = pd.read_csv(file, sep=";")
        num_rows = len(df)
        if num_rows > 1:
            csv_files.append(file)
    except Exception:
        logger.error(f"Error reading file {file}")


# Import logos providers
aws_provider_logo = html.Img(
    src="assets/images/providers/aws_provider.png", alt="aws provider"
)
azure_provider_logo = html.Img(
    src="assets/images/providers/azure_provider.png", alt="azure provider"
)
gcp_provider_logo = html.Img(
    src="assets/images/providers/gcp_provider.png", alt="gcp provider"
)
ks8_provider_logo = html.Img(
    src="assets/images/providers/k8s_provider.png", alt="k8s provider"
)
m365_provider_logo = html.Img(
    src="assets/images/providers/m365_provider.png", alt="m365 provider"
)
alibabacloud_provider_logo = html.Img(
    src="assets/images/providers/alibabacloud_provider.png", alt="alibabacloud provider"
)


def load_csv_files(csv_files):
    """Load CSV files into a single pandas DataFrame."""
    dfs = []
    for file in csv_files:
        account_columns = ["ACCOUNT_ID", "ACCOUNT_UID", "SUBSCRIPTION"]

        df_sample = pd.read_csv(file, sep=";", on_bad_lines="skip", nrows=1)

        dtype_dict = {}
        for col in account_columns:
            if col in df_sample.columns:
                dtype_dict[col] = str

        # Read the full file with proper dtypes
        df = pd.read_csv(file, sep=";", on_bad_lines="skip", dtype=dtype_dict)

        if "CHECK_ID" in df.columns:
            if "TIMESTAMP" in df.columns or df["PROVIDER"].unique() == "aws":
                dfs.append(df.astype(str))
    # Handle the case where there are no files
    try:
        data = pd.concat(dfs, ignore_index=True)
    except ValueError:
        data = None
    return data


data = load_csv_files(csv_files)

if data is None:
    # Initializing the Dash App
    dash.register_page(__name__, path="/")

    layout = html.Div(
        [
            html.H1(
                "No data available",
                className="text-prowler-stone-900 text-2xxl font-bold",
            ),
            html.Div(className="flex justify-between border-b border-prowler-500 pb-3"),
            html.Div(
                [
                    html.Div(
                        "Check the data folder to see if the files are in the correct format",
                        className="text-prowler-stone-900 text-lg font-bold",
                    )
                ],
                className="grid gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-3 lg:gap-y-0",
            ),
        ]
    )
else:
    # This handles the case where we are using v3 outputs
    if "ASSESSMENT_START_TIME" in data.columns:
        data["ASSESSMENT_START_TIME"] = data["ASSESSMENT_START_TIME"].str.replace(
            "T", " "
        )
        data.rename(columns={"ASSESSMENT_START_TIME": "TIMESTAMP_AUX"}, inplace=True)
        # Unify the columns
        data["TIMESTAMP"] = data.apply(
            lambda x: (
                x["TIMESTAMP_AUX"] if pd.isnull(x["TIMESTAMP"]) else x["TIMESTAMP"]
            ),
            axis=1,
        )
    if "ACCOUNT_ID" in data.columns:
        data.rename(columns={"ACCOUNT_ID": "ACCOUNT_UID_AUX"}, inplace=True)
        data["ACCOUNT_UID"] = data.apply(
            lambda x: (
                x["ACCOUNT_UID_AUX"]
                if pd.isnull(x["ACCOUNT_UID"])
                else x["ACCOUNT_UID"]
            ),
            axis=1,
        )
    # Rename the column RESOURCE_ID to RESOURCE_UID
    if "RESOURCE_ID" in data.columns:
        data.rename(columns={"RESOURCE_ID": "RESOURCE_UID_AUX"}, inplace=True)
        data["RESOURCE_UID"] = data.apply(
            lambda x: (
                x["RESOURCE_UID_AUX"]
                if pd.isnull(x["RESOURCE_UID"])
                else x["RESOURCE_UID"]
            ),
            axis=1,
        )
    # Rename the column "SUBSCRIPTION" to "ACCOUNT_UID"
    if "SUBSCRIPTION" in data.columns:
        data.rename(columns={"SUBSCRIPTION": "ACCOUNT_UID_AUX"}, inplace=True)
        data["ACCOUNT_UID"] = data.apply(
            lambda x: (
                x["ACCOUNT_UID_AUX"]
                if pd.isnull(x["ACCOUNT_UID"])
                else x["ACCOUNT_UID"]
            ),
            axis=1,
        )

    # For the timestamp, remove the two columns and keep only the date
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])
    # Handle findings from v3 outputs
    if "FINDING_UNIQUE_ID" in data.columns:
        data.rename(columns={"FINDING_UNIQUE_ID": "FINDING_UID"}, inplace=True)
    if "ACCOUNT_ID" in data.columns:
        data.rename(columns={"ACCOUNT_ID": "ACCOUNT_UID"}, inplace=True)
    if "ASSESSMENT_START_TIME" in data.columns:
        data.rename(columns={"ASSESSMENT_START_TIME": "TIMESTAMP"}, inplace=True)
    if "RESOURCE_ID" in data.columns:
        data.rename(columns={"RESOURCE_ID": "RESOURCE_UID"}, inplace=True)

    # Remove dupplicates on the finding_uid colummn but keep the last one taking into account the timestamp
    data["DATE"] = data["TIMESTAMP"].dt.date
    data = (
        data.sort_values("TIMESTAMP")
        .groupby(["DATE", "FINDING_UID"], as_index=False)
        .last()
    )
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])

    data["ASSESSMENT_TIME"] = data["TIMESTAMP"].dt.strftime("%Y-%m-%d")
    data_valid = pd.DataFrame()
    for account in data["ACCOUNT_UID"].unique():
        all_times = data[data["ACCOUNT_UID"] == account]["ASSESSMENT_TIME"].unique()
        all_times.sort()
        all_times = all_times[::-1]
        times = []
        # select the last ASSESSMENT_TIME in the day for each account
        for time in all_times:
            if time.split(" ")[0] not in [
                times[i].split(" ")[0] for i in range(len(times))
            ]:
                times.append(time)
        # select the data from the last ASSESSMENT_TIME of the day
        data_valid = pd.concat(
            [
                data_valid,
                data[
                    (data["ACCOUNT_UID"] == account)
                    & (data["ASSESSMENT_TIME"].isin(times))
                ],
            ]
        )
    data = data_valid
    # Select only the day in the data
    data["ASSESSMENT_TIME"] = data["ASSESSMENT_TIME"].apply(lambda x: x.split(" ")[0])

    data["TIMESTAMP"] = data["TIMESTAMP"].dt.strftime("%Y-%m-%d")
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])

    # Assessment Date Dropdown
    assesment_times = list(data["ASSESSMENT_TIME"].unique())
    assesment_times.sort()
    assesment_times.reverse()
    date_dropdown = create_date_dropdown(assesment_times)

    # Cloud Account Dropdown
    accounts = []
    if "ACCOUNT_NAME" in data.columns:
        for account in data["ACCOUNT_NAME"].unique():
            if "azure" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                accounts.append(account + " - AZURE")
            if "gcp" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                accounts.append(account + " - GCP")
            if "m365" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                accounts.append(account + " - M365")

    if "ACCOUNT_UID" in data.columns:
        for account in data["ACCOUNT_UID"].unique():
            if "aws" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                accounts.append(account + " - AWS")
            if "kubernetes" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                accounts.append(account + " - K8S")
            if "alibabacloud" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                accounts.append(account + " - ALIBABACLOUD")

    account_dropdown = create_account_dropdown(accounts)

    # Region Dropdown
    # Handle the case where there is location column
    if "LOCATION" in data.columns:
        data["REGION"] = data["LOCATION"]
    # Handle the case where there is no region column
    if "REGION" not in data.columns:
        data["REGION"] = "-"
    # Handle the case where the region is null
    data["REGION"].fillna("-")
    regions = ["All"] + list(data["REGION"].unique())
    regions = [x for x in regions if str(x) != "nan" and x.__class__.__name__ == "str"]
    # Correct the values
    options = []
    for value in regions:
        if " " in value:
            options.append(value.split(" ")[1])
        else:
            options.append(value)
    regions = options
    region_dropdown = create_region_dropdown(regions)

    # Severity Dropdown
    severity = ["All"] + list(data["SEVERITY"].unique())
    severity = [
        x for x in severity if str(x) != "nan" and x.__class__.__name__ == "str"
    ]

    severity_dropdown = create_severity_dropdown(severity)

    # Service Dropdown
    services = []
    for service in data["SERVICE_NAME"].unique():
        if "aws" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - AWS")
        if "kubernetes" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - K8S")
        if "azure" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - AZURE")
        if "gcp" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - GCP")
        if "m365" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - M365")
        if "alibabacloud" in list(data[data["SERVICE_NAME"] == service]["PROVIDER"]):
            services.append(service + " - ALIBABACLOUD")

    services = ["All"] + services
    services = [
        x for x in services if str(x) != "nan" and x.__class__.__name__ == "str"
    ]

    service_dropdown = create_service_dropdown(services)

    # Provider Dropdown
    providers = ["All"] + list(data["PROVIDER"].unique())
    providers = [
        x for x in providers if str(x) != "nan" and x.__class__.__name__ == "str"
    ]
    provider_dropdown = create_provider_dropdown(providers)

    # Create the download button
    download_button_csv = html.Button(
        "Download this table as CSV",
        id="download_link_csv",
        n_clicks=0,
        className="border-solid border-2 border-prowler-stone-900/10 hover:border-solid hover:border-2 hover:border-prowler-stone-900/10 text-prowler-stone-900 inline-block px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 flex justify-end w-fit",
    )
    download_button_xlsx = html.Button(
        "Download this table as XLSX",
        id="download_link_xlsx",
        n_clicks=0,
        className="border-solid border-2 border-prowler-stone-900/10 hover:border-solid hover:border-2 hover:border-prowler-stone-900/10 text-prowler-stone-900 inline-block px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 flex justify-end w-fit",
    )

    # Create the table row dropdown
    table_row_values = [-1]
    table_row_dropdown = create_table_row_dropdown(table_row_values)

    # Create the status dropdown
    status = ["All"] + list(data["STATUS"].unique())
    status = [x for x in status if str(x) != "nan" and x.__class__.__name__ == "str"]

    status_dropdown = create_status_dropdown(status)

    # Create the category dropdown
    categories = []
    if "CATEGORIES" in data.columns:
        for cat_list in data["CATEGORIES"].dropna().unique():
            if cat_list and str(cat_list) != "nan":
                for cat in str(cat_list).split(","):
                    cat = cat.strip()
                    if cat and cat not in categories:
                        categories.append(cat)
    categories = ["All"] + sorted(categories)
    category_dropdown = create_category_dropdown(categories)
    table_div_header = []
    table_div_header.append(
        html.Div(
            [
                html.Div(
                    [
                        html.Span(
                            "Check Name",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_check_name",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[40.5%] 2xl:w-[71.5%]",
                ),
                html.Div(
                    [
                        html.Span(
                            "Severity",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_severity",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[11%] 2xl:w-[15.5%]",
                ),
                html.Div(
                    [
                        html.Span(
                            "Status",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_status",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[9%] 2xl:w-[12.5%]",
                ),
                html.Div(
                    [
                        html.Span(
                            "Region",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_region",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[10%] 2xl:w-[14%]",
                ),
                html.Div(
                    [
                        html.Span(
                            "Service",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_service",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[13.5%] 2xl:w-[14%]",
                ),
                html.Div(
                    [
                        html.Span(
                            "Account",
                            className="text-prowler-stone-900 uppercase text-sm xl:text-md font-bold",
                        ),
                        html.Button(
                            html.Img(
                                src="assets/images/icons/arrows.svg",
                                style={
                                    "width": "1rem",
                                    "height": "1rem",
                                    "margin-left": "0.2rem",
                                    "margin-top": "0.2rem",
                                },
                            ),
                            id="sort_button_account",
                            n_clicks=0,
                        ),
                    ],
                    className="w-[15%] 2xl:w-[15.5%]",
                ),
            ],
            className="grid grid-cols-auto w-full",
            style={
                "display": "flex",
            },
        )
    )

    table_div_header = html.Div(table_div_header, id="table-div-header")

    # Initializing the Dash App
    dash.register_page(__name__, path="/")

    # Create the layout
    layout = create_layout_overview(
        account_dropdown,
        date_dropdown,
        region_dropdown,
        download_button_csv,
        download_button_xlsx,
        severity_dropdown,
        service_dropdown,
        provider_dropdown,
        table_row_dropdown,
        status_dropdown,
        category_dropdown,
        table_div_header,
        len(data["PROVIDER"].unique()),
    )


# Callback to display selected value
@callback(
    [
        Output("status_graph", "children"),
        Output("two_pie_chart", "children"),
        Output("line_plot", "children"),
        Output("table", "children"),
        Output("download-data", "data"),
        Output("cloud-account-filter", "value"),
        Output("cloud-account-filter", "options"),
        Output("region-filter", "value"),
        Output("region-filter", "options"),
        Output("report-date-filter", "value"),
        Output("aws_card", "children"),
        Output("azure_card", "children"),
        Output("gcp_card", "children"),
        Output("k8s_card", "children"),
        Output("m365_card", "children"),
        Output("alibabacloud_card", "children"),
        Output("subscribe_card", "children"),
        Output("info-file-over", "title"),
        Output("severity-filter", "value"),
        Output("severity-filter", "options"),
        Output("service-filter", "value"),
        Output("provider-filter", "value"),
        Output("provider-filter", "options"),
        Output("service-filter", "options"),
        Output("table-rows", "value"),
        Output("table-rows", "options"),
        Output("status-filter", "value"),
        Output("status-filter", "options"),
        Output("category-filter", "value"),
        Output("category-filter", "options"),
        Output("aws_card", "n_clicks"),
        Output("azure_card", "n_clicks"),
        Output("gcp_card", "n_clicks"),
        Output("k8s_card", "n_clicks"),
        Output("m365_card", "n_clicks"),
        Output("alibabacloud_card", "n_clicks"),
    ],
    Input("cloud-account-filter", "value"),
    Input("region-filter", "value"),
    Input("report-date-filter", "value"),
    Input("download_link_csv", "n_clicks"),
    Input("download_link_xlsx", "n_clicks"),
    Input("severity-filter", "value"),
    Input("service-filter", "value"),
    Input("provider-filter", "value"),
    Input("table-rows", "value"),
    Input("status-filter", "value"),
    Input("category-filter", "value"),
    Input("search-input", "value"),
    Input("aws_card", "n_clicks"),
    Input("azure_card", "n_clicks"),
    Input("gcp_card", "n_clicks"),
    Input("k8s_card", "n_clicks"),
    Input("m365_card", "n_clicks"),
    Input("sort_button_check_name", "n_clicks"),
    Input("sort_button_severity", "n_clicks"),
    Input("sort_button_status", "n_clicks"),
    Input("sort_button_region", "n_clicks"),
    Input("sort_button_service", "n_clicks"),
    Input("sort_button_account", "n_clicks"),
    Input("alibabacloud_card", "n_clicks"),
)
def filter_data(
    cloud_account_values,
    region_account_values,
    assessment_value,
    n_clicks_csv,
    n_clicks_xlsx,
    severity_values,
    service_values,
    provider_values,
    table_row_values,
    status_values,
    category_values,
    search_value,
    aws_clicks,
    azure_clicks,
    gcp_clicks,
    k8s_clicks,
    m365_clicks,
    sort_button_check_name,
    sort_button_severity,
    sort_button_status,
    sort_button_region,
    sort_button_service,
    sort_button_account,
    alibabacloud_clicks,
):
    # Use n_clicks for vulture
    n_clicks_csv = n_clicks_csv
    n_clicks_xlsx = n_clicks_xlsx
    # Filter the data
    filtered_data = data.copy()

    if aws_clicks > 0:
        filtered_data = data.copy()
        if aws_clicks % 2 != 0 and "aws" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "aws"]
            azure_clicks = 0
            gcp_clicks = 0
            k8s_clicks = 0
            m365_clicks = 0
            alibabacloud_clicks = 0
    if azure_clicks > 0:
        filtered_data = data.copy()
        if azure_clicks % 2 != 0 and "azure" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "azure"]
            aws_clicks = 0
            gcp_clicks = 0
            k8s_clicks = 0
            m365_clicks = 0
            alibabacloud_clicks = 0
    if gcp_clicks > 0:
        filtered_data = data.copy()
        if gcp_clicks % 2 != 0 and "gcp" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "gcp"]
            aws_clicks = 0
            azure_clicks = 0
            k8s_clicks = 0
            m365_clicks = 0
            alibabacloud_clicks = 0
    if k8s_clicks > 0:
        filtered_data = data.copy()
        if k8s_clicks % 2 != 0 and "kubernetes" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "kubernetes"]
            aws_clicks = 0
            azure_clicks = 0
            gcp_clicks = 0
            m365_clicks = 0
            alibabacloud_clicks = 0
    if m365_clicks > 0:
        filtered_data = data.copy()
        if m365_clicks % 2 != 0 and "m365" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "m365"]
            aws_clicks = 0
            azure_clicks = 0
            gcp_clicks = 0
            k8s_clicks = 0
            alibabacloud_clicks = 0
    if alibabacloud_clicks > 0:
        filtered_data = data.copy()
        if alibabacloud_clicks % 2 != 0 and "alibabacloud" in list(data["PROVIDER"]):
            filtered_data = filtered_data[filtered_data["PROVIDER"] == "alibabacloud"]
            aws_clicks = 0
            azure_clicks = 0
            gcp_clicks = 0
            k8s_clicks = 0
            m365_clicks = 0
    # For all the data, we will add to the status column the value 'MUTED (FAIL)' and 'MUTED (PASS)' depending on the value of the column 'STATUS' and 'MUTED'
    if "MUTED" in filtered_data.columns:
        filtered_data["STATUS"] = filtered_data.apply(
            lambda x: (
                "MUTED (FAIL)"
                if x["STATUS"] == "FAIL" and x["MUTED"] == "True"
                else x["STATUS"]
            ),
            axis=1,
        )
        filtered_data["STATUS"] = filtered_data.apply(
            lambda x: (
                "MUTED (PASS)"
                if x["STATUS"] == "PASS" and x["MUTED"] == "True"
                else x["STATUS"]
            ),
            axis=1,
        )
        filtered_data["STATUS"] = filtered_data.apply(
            lambda x: (
                "MUTED (MANUAL)"
                if x["STATUS"] == "MANUAL" and x["MUTED"] == "True"
                else x["STATUS"]
            ),
            axis=1,
        )

    # Take the latest date of de data
    account_date = filtered_data["ASSESSMENT_TIME"].unique()
    account_date.sort()
    account_date = account_date[::-1]

    start_date = datetime.strptime(account_date[0], "%Y-%m-%d") - timedelta(days=7)
    end_date = datetime.strptime(account_date[0], "%Y-%m-%d")

    filtered_data_sp = filtered_data[
        (filtered_data["TIMESTAMP"] >= start_date)
        & (filtered_data["TIMESTAMP"] <= end_date)
    ]
    # We are taking the latest date if there is only one account
    # Filter Assessment Time
    if assessment_value in account_date:
        updated_assessment_value = assessment_value
    else:
        updated_assessment_value = account_date[0]
        assessment_value = account_date[0]
    filtered_data = filtered_data[
        filtered_data["ASSESSMENT_TIME"] == updated_assessment_value
    ]

    # Select the files in the list_files that have the same date as the selected date
    list_files = []
    for file in csv_files:
        df = pd.read_csv(file, sep=";", on_bad_lines="skip")
        if "CHECK_ID" in df.columns:
            if "TIMESTAMP" in df.columns or df["PROVIDER"].unique() == "aws":
                # This handles the case where we are using v3 outputs
                if "TIMESTAMP" not in df.columns and df["PROVIDER"].unique() == "aws":
                    # Rename the column 'ASSESSMENT_START_TIME' to 'TIMESTAMP'
                    df["ASSESSMENT_START_TIME"] = df[
                        "ASSESSMENT_START_TIME"
                    ].str.replace("T", " ")
                    df.rename(
                        columns={"ASSESSMENT_START_TIME": "TIMESTAMP"}, inplace=True
                    )
                    df["TIMESTAMP"] = df["TIMESTAMP"].str.replace("T", " ")
                df["TIMESTAMP"] = pd.to_datetime(df["TIMESTAMP"])
                df["TIMESTAMP"] = df["TIMESTAMP"].dt.strftime("%Y-%m-%d")
                if df["TIMESTAMP"][0] == updated_assessment_value:
                    list_files.append(file)
    # append all the names of the files
    files_names = []
    for file in list_files:
        files_names.append(file.split("/")[-1])

    list_files = ",\n".join(files_names)
    list_files = "Files Scanned:\n" + list_files

    # Change the account selector to the values that are allowed
    filtered_data = filtered_data[
        filtered_data["ASSESSMENT_TIME"] == updated_assessment_value
    ]

    # fill all_account_ids with the account_uid for the provider aws and kubernetes
    all_account_ids = []
    if "ACCOUNT_UID" in filtered_data.columns:
        for account in filtered_data["ACCOUNT_UID"].unique():
            if "aws" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                all_account_ids.append(account)
            if "kubernetes" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                all_account_ids.append(account)
            if "alibabacloud" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                all_account_ids.append(account)

    all_account_names = []
    if "ACCOUNT_NAME" in filtered_data.columns:
        for account in filtered_data["ACCOUNT_NAME"].unique():
            if "azure" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                all_account_names.append(account)
            if "gcp" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                all_account_names.append(account)
            if "m365" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
                all_account_names.append(account)

    all_items = all_account_ids + all_account_names + ["All"]

    cloud_accounts_options = ["All"]
    for item in all_items:
        if item not in cloud_accounts_options and item.__class__.__name__ == "str":
            # append the provider name depending on the account
            if "ACCOUNT_UID" in filtered_data.columns:
                if "aws" in list(data[data["ACCOUNT_UID"] == item]["PROVIDER"]):
                    cloud_accounts_options.append(item + " - AWS")
                if "kubernetes" in list(data[data["ACCOUNT_UID"] == item]["PROVIDER"]):
                    cloud_accounts_options.append(item + " - K8S")
                if "alibabacloud" in list(
                    data[data["ACCOUNT_UID"] == item]["PROVIDER"]
                ):
                    cloud_accounts_options.append(item + " - ALIBABACLOUD")
            if "ACCOUNT_NAME" in filtered_data.columns:
                if "azure" in list(data[data["ACCOUNT_NAME"] == item]["PROVIDER"]):
                    cloud_accounts_options.append(item + " - AZURE")
                if "gcp" in list(data[data["ACCOUNT_NAME"] == item]["PROVIDER"]):
                    cloud_accounts_options.append(item + " - GCP")
                if "m365" in list(data[data["ACCOUNT_NAME"] == item]["PROVIDER"]):
                    cloud_accounts_options.append(item + " - M365")

    # Filter ACCOUNT
    if cloud_account_values == ["All"]:
        updated_cloud_account_values = all_items
    elif "All" in cloud_account_values and len(cloud_account_values) > 1:
        updated_cloud_account_values = []
        # Remove 'All' from the list
        cloud_account_values.remove("All")
        for item in cloud_account_values:
            updated_cloud_account_values.append(item.split(" - ")[0])
    elif len(cloud_account_values) == 0:
        updated_cloud_account_values = all_items
        cloud_account_values = ["All"]
    else:
        updated_cloud_account_values = []
        for item in cloud_account_values:
            updated_cloud_account_values.append(item.split(" - ")[0])
    values_choice = []
    for item in updated_cloud_account_values:
        if item not in values_choice:
            values_choice.append(item)

    # Apply the filter
    if (
        "ACCOUNT_UID" in filtered_data.columns
        and "ACCOUNT_NAME" in filtered_data.columns
    ):
        filtered_data = filtered_data[
            filtered_data["ACCOUNT_UID"].isin(values_choice)
            | filtered_data["ACCOUNT_NAME"].isin(values_choice)
        ]
    elif "ACCOUNT_UID" in filtered_data.columns:
        filtered_data = filtered_data[filtered_data["ACCOUNT_UID"].isin(values_choice)]
    elif "ACCOUNT_NAME" in filtered_data.columns:
        filtered_data = filtered_data[filtered_data["ACCOUNT_NAME"].isin(values_choice)]

    # Filter REGION

    # Check if filtered data contains an aws account
    if "REGION" not in filtered_data.columns:
        filtered_data["REGION"] = "-"
    if "LOCATION" in filtered_data.columns:
        filtered_data.rename(columns={"LOCATION": "REGION"}, inplace=True)
    if region_account_values == ["All"]:
        updated_region_account_values = filtered_data["REGION"].unique()
    elif "All" in region_account_values and len(region_account_values) > 1:
        # Remove 'All' from the list
        region_account_values.remove("All")
        updated_region_account_values = region_account_values
    elif len(region_account_values) == 0:
        updated_region_account_values = filtered_data["REGION"].unique()
        region_account_values = ["All"]
    else:
        updated_region_account_values = region_account_values

    filtered_data = filtered_data[
        filtered_data["REGION"].isin(updated_region_account_values)
    ]

    region_filter_options = ["All"] + list(filtered_data["REGION"].unique())
    # clean the region_filter_options from null values
    region_filter_options = [
        x
        for x in region_filter_options
        if str(x) != "nan" and x.__class__.__name__ == "str"
    ]
    # Correct the values
    options = []
    for value in region_filter_options:
        if " " in value:
            options.append(value.split(" ")[1])
        else:
            options.append(value)

    region_filter_options = options

    # Filter Severity
    if severity_values == ["All"]:
        updated_severity_values = filtered_data["SEVERITY"].unique()
    elif "All" in severity_values and len(severity_values) > 1:
        # Remove 'All' from the list
        severity_values.remove("All")
        updated_severity_values = severity_values
    elif len(severity_values) == 0:
        updated_severity_values = filtered_data["SEVERITY"].unique()
        severity_values = ["All"]
    else:
        updated_severity_values = severity_values

    filtered_data = filtered_data[
        filtered_data["SEVERITY"].isin(updated_severity_values)
    ]

    severity_filter_options = ["All"] + list(filtered_data["SEVERITY"].unique())

    service_filter_options = ["All"]

    all_items = filtered_data["SERVICE_NAME"].unique()

    for item in all_items:
        if item not in service_filter_options and item.__class__.__name__ == "str":
            if "aws" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - AWS")
            if "kubernetes" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - K8S")
            if "azure" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - AZURE")
            if "gcp" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - GCP")
            if "m365" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - M365")
            if "alibabacloud" in list(
                filtered_data[filtered_data["SERVICE_NAME"] == item]["PROVIDER"]
            ):
                service_filter_options.append(item + " - ALIBABACLOUD")

    # Filter Service
    if service_values == ["All"]:
        updated_service_values = filtered_data["SERVICE_NAME"].unique()
    elif "All" in service_values and len(service_values) > 1:
        # Remove 'All' from the list
        updated_service_values = []
        service_values.remove("All")
        for item in service_values:
            updated_service_values.append(item.split(" - ")[0])
    elif len(service_values) == 0:
        updated_service_values = filtered_data["SERVICE_NAME"].unique()
        service_values = ["All"]
    else:
        updated_service_values = []
        for item in service_values:
            updated_service_values.append(item.split(" - ")[0])

    filtered_data = filtered_data[
        filtered_data["SERVICE_NAME"].isin(updated_service_values)
    ]

    provider_filter_options = ["All"] + list(filtered_data["PROVIDER"].unique())

    # Filter Provider
    if provider_values == ["All"]:
        updated_provider_values = filtered_data["PROVIDER"].unique()
    elif "All" in provider_values and len(provider_values) > 1:
        # Remove 'All' from the list
        provider_values.remove("All")
        updated_provider_values = provider_values
    elif len(provider_values) == 0:
        updated_provider_values = filtered_data["PROVIDER"].unique()
        provider_values = ["All"]
    else:
        updated_provider_values = provider_values

    filtered_data = filtered_data[
        filtered_data["PROVIDER"].isin(updated_provider_values)
    ]

    # Filter Status
    if status_values == ["All"]:
        updated_status_values = filtered_data["STATUS"].unique()
    elif "All" in status_values and len(status_values) > 1:
        # Remove 'All' from the list
        status_values.remove("All")
        updated_status_values = status_values
    elif len(status_values) == 0:
        updated_status_values = filtered_data["STATUS"].unique()
        status_values = ["All"]
    else:
        updated_status_values = status_values

    filtered_data = filtered_data[filtered_data["STATUS"].isin(updated_status_values)]

    status_filter_options = ["All"] + list(filtered_data["STATUS"].unique())

    # Filter Category
    if "CATEGORIES" in filtered_data.columns:
        if category_values == ["All"]:
            updated_category_values = None
        elif "All" in category_values and len(category_values) > 1:
            category_values.remove("All")
            updated_category_values = category_values
        elif len(category_values) == 0:
            updated_category_values = None
            category_values = ["All"]
        else:
            updated_category_values = category_values

        if updated_category_values:
            filtered_data = filtered_data[
                filtered_data["CATEGORIES"].apply(
                    lambda x: any(
                        cat.strip() in updated_category_values
                        for cat in str(x).split(",")
                        if str(x) != "nan"
                    )
                )
            ]

        category_filter_options = ["All"]
        for cat_list in filtered_data["CATEGORIES"].dropna().unique():
            if cat_list and str(cat_list) != "nan":
                for cat in str(cat_list).split(","):
                    cat = cat.strip()
                    if cat and cat not in category_filter_options:
                        category_filter_options.append(cat)
        category_filter_options = sorted(category_filter_options)
    else:
        category_filter_options = ["All"]

    if len(filtered_data_sp) == 0:
        fig = px.pie()
        fig.update_layout(
            paper_bgcolor="#FFF",
        )
        line_chart = dcc.Graph(figure=fig, config={"displayModeBar": False})
    else:
        try:
            ########################################################
            """Line  PLOT 1"""
            ########################################################
            # Formatting date columns
            filtered_data_sp["TIMESTAMP_formatted"] = pd.to_datetime(
                filtered_data_sp["TIMESTAMP"]
            ).dt.strftime("%Y-%m-%d")
            filtered_data_sp["TIMESTAMP_formatted"] = pd.to_datetime(
                filtered_data_sp["TIMESTAMP_formatted"]
            )
            # Generate a date range for the last 30 days
            date_range = pd.date_range(start=start_date, end=end_date)

            # Format the dates as '%Y-%m-%d'
            date_range.strftime("%Y-%m-%d").tolist()

            # Dataframe with count of PASS FAIL Statuses
            satus_df = (
                pd.DataFrame(
                    filtered_data_sp.groupby(["TIMESTAMP_formatted"])[
                        "STATUS"
                    ].value_counts()
                )
                .rename(columns={"STATUS": "Status_count"})
                .reset_index()
            )
            satus_df = satus_df.rename(columns={"TIMESTAMP_formatted": "date"})

            # Generate all possible combinations
            statuses = list(filtered_data_sp["STATUS"].unique())
            combinations = list(product(date_range, statuses))

            all_date_combinations = pd.DataFrame(
                combinations, columns=["date", "STATUS"]
            )

            result_df = all_date_combinations.merge(
                satus_df, on=["date", "STATUS"], how="left"
            )

            result_df.rename(columns={"count": "Status_count"}, inplace=True)

            result_df["Status_count"].fillna(0, inplace=True)

            color_mapping = {
                "FAIL": fail_color,
                "PASS": pass_color,
                "INFO": info_color,
                "MANUAL": manual_color,
                "MUTED (FAIL)": muted_fail_color,
                "MUTED (PASS)": muted_pass_color,
                "MUTED (MANUAL)": muted_manual_color,
            }

            # Create a single line plot for both 'FAIL' and 'PASS' statuses
            fig6 = px.line(
                result_df,
                x="date",
                y="Status_count",
                color="STATUS",
                color_discrete_map=color_mapping,
            )
            fig6.update_traces(mode="markers+lines", marker=dict(size=8))
            fig6.update_layout(
                margin=dict(l=0, r=0, t=0, b=0),
                xaxis_title="",
                yaxis_title="",
                template="plotly",
                legend=dict(x=0.02, y=0.98),
                paper_bgcolor="#FFF",
                font=dict(size=12, color="#292524"),
            )

            line_chart = dcc.Graph(
                figure=fig6,
                config={"displayModeBar": False, "scrollZoom": False},
                style={"height": "300px", "overflow-y": "auto"},
                className="max-h-[300px]",
            )
        except Exception:
            fig = px.pie()
            fig.update_layout(
                paper_bgcolor="#FFF",
            )
            line_chart = dcc.Graph(figure=fig, config={"displayModeBar": False})

    # If the data is out of range Make the while dashaboard empty
    if len(filtered_data) == 0:
        fig = px.pie()
        pie_2 = dcc.Graph(
            figure=fig,
            config={"displayModeBar": False},
        )
        pie_3 = dcc.Graph(
            figure=fig,
            config={"displayModeBar": False},
        )
        table = dcc.Graph(figure=fig, config={"displayModeBar": False})

    else:
        # Status Pie Chart
        df1 = filtered_data[filtered_data["STATUS"] == "FAIL"]

        color_mapping_status = {
            "FAIL": fail_color,
            "PASS": pass_color,
            "LOW": info_color,
            "MANUAL": manual_color,
            "WARNING": muted_fail_color,
            "MUTED (FAIL)": muted_fail_color,
            "MUTED (PASS)": muted_pass_color,
            "MUTED (MANUAL)": "#b33696",
            "MUTED (WARNING)": "#c7a45d",
        }
        # Define custom colors
        color_mapping_severity = {
            "critical": critical_color,
            "high": high_color,
            "medium": medium_color,
            "low": low_color,
            "informational": informational_color,
        }

        # Use the color_discrete_map parameter to map categories to custom colors
        fig2 = px.pie(
            filtered_data,
            names="STATUS",
            hole=0.7,
            color="STATUS",
            color_discrete_map=color_mapping_status,
        )
        fig2.update_traces(
            hovertemplate=None,
            textposition="outside",
            textinfo="percent+label",
            rotation=50,
        )

        fig2.update_layout(
            margin=dict(l=0, r=0, t=50, b=0),
            autosize=True,
            showlegend=False,
            font=dict(size=14, color="#292524"),
            hoverlabel=dict(font_size=12),
            paper_bgcolor="#FFF",
        )

        pie_2 = dcc.Graph(
            figure=fig2,
            config={"displayModeBar": False},
            style={"height": "300px", "overflow-y": "auto"},
        )

        # Prepare bar chart data only if df1 has FAIL findings
        if len(df1) > 0:
            color_bars = [
                color_mapping_severity[severity]
                for severity in df1["SEVERITY"].value_counts().index
            ]
            bar_data = [
                go.Bar(
                    x=df1["SEVERITY"].value_counts().index,
                    y=df1["SEVERITY"].value_counts().values,
                    marker=dict(color=color_bars),
                    textposition="auto",
                )
            ]
        else:
            bar_data = []

        figure_bars = go.Figure(
            data=bar_data,
            layout=go.Layout(
                paper_bgcolor="#FFF",
                font=dict(size=12, color="#292524"),
                margin=dict(l=20, r=20, t=0, b=150),
            ),
        )

        pie_3 = dcc.Graph(
            figure=figure_bars,
            config={"displayModeBar": False},
            style={"height": "400px", "overflow-y": "auto", "margin-top": "0px"},
        )

        # TABLE
        severity_dict = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "informational": 0,
        }

        filtered_data["SEVERITY"] = filtered_data["SEVERITY"].map(severity_dict)
        filtered_data = filtered_data.sort_values(by=["SEVERITY"], ascending=False)
        filtered_data["SEVERITY"] = filtered_data["SEVERITY"].replace(
            {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "informational"}
        )

        table_row_options = []

        # Calculate table row options as percentages
        percentages = [0.05, 0.10, 0.25, 0.50, 0.75, 1.0]
        total_rows = len(filtered_data)
        for pct in percentages:
            value = max(1, int(total_rows * pct))
            label = f"{int(pct * 100)}%"
            table_row_options.append({"label": label, "value": value})

        # Default to 25% if not set
        if table_row_values is None or table_row_values == -1:
            table_row_values = table_row_options[0]["value"]

        # For the values that are nan or none, replace them with ""
        filtered_data = filtered_data.replace({np.nan: ""})
        filtered_data = filtered_data.replace({None: ""})
        filtered_data = filtered_data.replace({"nan": ""})

        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
            "informational": 0,
        }

        severity_mapping_reverse = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical",
            0: "informational",
        }

        status_mapping = {
            "MANUAL": 0,
            "INFO": 1,
            "MUTED (MANUAL)": 2,
            "MUTED (PASS)": 3,
            "PASS": 4,
            "MUTED (FAIL)": 5,
            "FAIL": 6,
        }

        status_mapping_reverse = {
            0: "MANUAL",
            1: "INFO",
            2: "MUTED (MANUAL)",
            3: "MUTED (PASS)",
            4: "PASS",
            5: "MUTED (FAIL)",
            6: "FAIL",
        }

        index_count = 0
        if search_value:
            search_value = search_value.lower()
            filtered_data = filtered_data[
                filtered_data["CHECK_TITLE"].str.lower().str.contains(search_value)
                | filtered_data["SERVICE_NAME"].str.lower().str.contains(search_value)
                | filtered_data["REGION"].str.lower().str.contains(search_value)
                | filtered_data["STATUS"].str.lower().str.contains(search_value)
            ]

        full_filtered_data = filtered_data.copy()
        filtered_data = filtered_data.head(table_row_values)
        # Sort the filtered_data
        if sort_button_check_name > 0:
            if sort_button_check_name % 2 != 0:
                filtered_data = filtered_data.sort_values(
                    by=["CHECK_TITLE"], ascending=True
                )
            else:
                filtered_data = filtered_data.sort_values(
                    by=["CHECK_TITLE"], ascending=False
                )
                sort_button_check_name = 0
            sort_button_severity = 0
            sort_button_status = 0
            sort_button_region = 0
            sort_button_service = 0
            sort_button_account = 0
        if sort_button_severity > 0:
            filtered_data["SEVERITY"] = filtered_data["SEVERITY"].map(severity_mapping)
            if sort_button_severity % 2 != 0:
                filtered_data = filtered_data.sort_values(
                    by=["SEVERITY"], ascending=True
                )
            else:
                filtered_data = filtered_data.sort_values(
                    by=["SEVERITY"], ascending=False
                )
                sort_button_severity = 0
            filtered_data["SEVERITY"] = filtered_data["SEVERITY"].map(
                severity_mapping_reverse
            )
            sort_button_check_name = 0
            sort_button_status = 0
            sort_button_region = 0
            sort_button_service = 0
            sort_button_account = 0
        if sort_button_status > 0:
            filtered_data["STATUS"] = filtered_data["STATUS"].map(status_mapping)
            if sort_button_status % 2 != 0:
                filtered_data = filtered_data.sort_values(by=["STATUS"], ascending=True)
            else:
                filtered_data = filtered_data.sort_values(
                    by=["STATUS"], ascending=False
                )
                sort_button_status = 0
            filtered_data["STATUS"] = filtered_data["STATUS"].map(
                status_mapping_reverse
            )
            sort_button_check_name = 0
            sort_button_severity = 0
            sort_button_region = 0
            sort_button_service = 0
            sort_button_account = 0
        if sort_button_region > 0:
            if sort_button_region % 2 != 0:
                filtered_data = filtered_data.sort_values(by=["REGION"], ascending=True)
            else:
                filtered_data = filtered_data.sort_values(
                    by=["REGION"], ascending=False
                )
                sort_button_region = 0
            sort_button_check_name = 0
            sort_button_severity = 0
            sort_button_status = 0
            sort_button_service = 0
            sort_button_account = 0
        if sort_button_service > 0:
            if sort_button_service % 2 != 0:
                filtered_data = filtered_data.sort_values(
                    by=["SERVICE_NAME"], ascending=True
                )
            else:
                filtered_data = filtered_data.sort_values(
                    by=["SERVICE_NAME"], ascending=False
                )
                sort_button_service = 0
            sort_button_check_name = 0
            sort_button_severity = 0
            sort_button_status = 0
            sort_button_region = 0
            sort_button_account = 0
        if sort_button_account > 0:
            if sort_button_account % 2 != 0:
                filtered_data = filtered_data.sort_values(
                    by=["ACCOUNT_UID"], ascending=True
                )
            else:
                filtered_data = filtered_data.sort_values(
                    by=["ACCOUNT_UID"], ascending=False
                )
                sort_button_account = 0
            sort_button_check_name = 0
            sort_button_severity = 0
            sort_button_status = 0
            sort_button_region = 0
            sort_button_service = 0

        # Remove column "assessment_time", this is done to undo the changes made in the data
        if "TIMESTAMP_AUX" in filtered_data.columns:
            filtered_data.drop(columns=["TIMESTAMP_AUX"], inplace=True)

        # For the account_id, we are going to add the provider name
        if "ACCOUNT_UID" in filtered_data.columns:
            for account in filtered_data["ACCOUNT_UID"].unique():
                if "aws" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - AWS")
                if "kubernetes" in list(
                    data[data["ACCOUNT_UID"] == account]["PROVIDER"]
                ):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - K8S")
                if "azure" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - AZURE")
                if "gcp" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - GCP")
                if "m365" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - M365")
                if "alibabacloud" in list(
                    data[data["ACCOUNT_UID"] == account]["PROVIDER"]
                ):
                    filtered_data.loc[
                        filtered_data["ACCOUNT_UID"] == account, "ACCOUNT_UID"
                    ] = (account + " - ALIBABACLOUD")

        table_collapsible = []
        for item in filtered_data.to_dict("records"):
            table_collapsible.append(
                generate_table(
                    item, index_count, color_mapping_severity, color_mapping_status
                )
            )
            index_count += 1

        table = html.Div(table_collapsible, id="table", className="overview-table")

    # Status Graphic
    status_graph = [
        html.Span(
            "Status",
            className="text-center text-prowler-stone-900 uppercase text-xs font-bold",
        ),
        html.Div(
            [
                pie_2,
            ],
            className="w-full",
        ),
    ]

    # Layout two pie charts
    two_pie_chart = [
        html.Span(
            "Severity",
            className="text-center text-prowler-stone-900 uppercase text-xs font-bold",
        ),
        html.Div(
            [
                pie_3,
            ],
            className="",
        ),
    ]

    # Layout Line PLOT
    line_plot = [
        html.Span(
            "Security Posture Evolution (last 7 days)",
            className="text-center text-prowler-stone-900 uppercase text-xs font-bold",
        ),
        html.Div([line_chart], className=""),
    ]

    # Table
    table_card = [
        html.Div([table], className="grid grid-cols-auto w-full"),
    ]

    # Create Provider Cards
    if "aws" in list(data["PROVIDER"].unique()):
        aws_card = create_provider_card(
            "aws", aws_provider_logo, "Accounts", full_filtered_data
        )
    else:
        aws_card = None
    if "azure" in list(data["PROVIDER"].unique()):
        azure_card = create_provider_card(
            "azure", azure_provider_logo, "Subscriptions", full_filtered_data
        )
    else:
        azure_card = None
    if "gcp" in list(data["PROVIDER"].unique()):
        gcp_card = create_provider_card(
            "gcp", gcp_provider_logo, "Projects", full_filtered_data
        )
    else:
        gcp_card = None
    if "kubernetes" in list(data["PROVIDER"].unique()):
        k8s_card = create_provider_card(
            "kubernetes", ks8_provider_logo, "Clusters", full_filtered_data
        )
    else:
        k8s_card = None
    if "m365" in list(data["PROVIDER"].unique()):
        m365_card = create_provider_card(
            "m365", m365_provider_logo, "Accounts", full_filtered_data
        )
    else:
        m365_card = None

    if "alibabacloud" in list(data["PROVIDER"].unique()):
        alibabacloud_card = create_provider_card(
            "alibabacloud", alibabacloud_provider_logo, "Accounts", full_filtered_data
        )
    else:
        alibabacloud_card = None

    # Subscribe to Prowler Cloud card
    subscribe_card = [
        html.Div(
            html.A(
                [
                    html.Img(src="assets/favicon.ico", className="w-5 mr-3"),
                    html.Span("Subscribe to Prowler Cloud"),
                ],
                href="https://prowler.pro/",
                target="_blank",
                className="text-prowler-stone-900 inline-flex px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 border-solid border-1 hover:border-prowler-stone-900/10 hover:border-solid hover:border-1 border-prowler-stone-900/10",
            ),
        )
    ]
    if (
        ctx.triggered_id == "download_link_csv"
        or ctx.triggered_id == "download_link_xlsx"
    ):
        if ctx.triggered_id == "download_link_csv":
            csv_data = dcc.send_data_frame(
                filtered_data.to_csv, "prowler-dashboard-export.csv", index=False
            )
        if ctx.triggered_id == "download_link_xlsx":
            csv_data = dcc.send_data_frame(
                filtered_data.to_excel,
                "prowler-dashboard-export.xlsx",
                index=False,
            )
        return (
            status_graph,
            two_pie_chart,
            line_plot,
            table_card,
            csv_data,
            cloud_account_values,
            cloud_accounts_options,
            region_account_values,
            region_filter_options,
            assessment_value,
            aws_card,
            azure_card,
            gcp_card,
            k8s_card,
            m365_card,
            alibabacloud_card,
            subscribe_card,
            list_files,
            severity_values,
            severity_filter_options,
            service_values,
            provider_values,
            provider_filter_options,
            service_filter_options,
            table_row_values,
            table_row_options,
            status_values,
            status_filter_options,
            category_values,
            category_filter_options,
            aws_clicks,
            azure_clicks,
            gcp_clicks,
            k8s_clicks,
            m365_clicks,
            alibabacloud_clicks,
        )
    else:
        return (
            status_graph,
            two_pie_chart,
            line_plot,
            table_card,
            None,
            cloud_account_values,
            cloud_accounts_options,
            region_account_values,
            region_filter_options,
            assessment_value,
            aws_card,
            azure_card,
            gcp_card,
            k8s_card,
            m365_card,
            alibabacloud_card,
            subscribe_card,
            list_files,
            severity_values,
            severity_filter_options,
            service_values,
            provider_values,
            provider_filter_options,
            service_filter_options,
            table_row_values,
            table_row_options,
            status_values,
            status_filter_options,
            category_values,
            category_filter_options,
            aws_clicks,
            azure_clicks,
            gcp_clicks,
            k8s_clicks,
            m365_clicks,
            alibabacloud_clicks,
        )


@callback(
    Output({"type": "collapse", "index": dash.dependencies.ALL}, "is_open"),
    [Input({"type": "toggle-collapse", "index": dash.dependencies.ALL}, "n_clicks")],
    [
        dash.dependencies.State(
            {"type": "collapse", "index": dash.dependencies.ALL}, "is_open"
        )
    ],
)
def toggle_collapse(n_clicks, is_open):
    n_clicks = n_clicks or 0
    triggered = callback_context.triggered[0]["prop_id"].split(".")[0]
    if triggered:
        idx = json.loads(triggered)["index"]
        is_open[idx] = not is_open[idx]
    return is_open


def generate_table(data, index, color_mapping_severity, color_mapping_status):
    return html.Div(
        [
            dbc.Card(
                [
                    dbc.CardHeader(
                        dbc.Row(
                            [
                                dbc.Col(
                                    [
                                        html.Button(
                                            html.Img(
                                                src="assets/images/icons/dropdown.svg",
                                                className="w-3",
                                            ),
                                            id={
                                                "type": "toggle-collapse",
                                                "index": index,
                                            },
                                            className="btn",
                                            style={
                                                "position": "relative",
                                                "top": "3px",
                                                "padding": "0",
                                            },
                                        ),
                                    ],
                                    width=1,
                                    className="w-[4%] 2xl:w-[2%]",
                                ),
                                dbc.Col(
                                    [
                                        html.H5(
                                            data["CHECK_TITLE"],
                                            className="card-title mb-0",
                                        ),
                                    ],
                                    width=4,
                                    className="pr-2 w-[36%] 2xl:w-[48%]",
                                ),
                                dbc.Col(
                                    [
                                        html.Span(
                                            data["SEVERITY"],
                                            className="text-white uppercase text-xs font-bold rounded-lg px-2 py-1",
                                            style={
                                                "background-color": color_mapping_severity[
                                                    data["SEVERITY"]
                                                ],
                                            },
                                        ),
                                    ],
                                    className="w-[11%]",
                                    width=1,
                                ),
                                dbc.Col(
                                    [
                                        html.Span(
                                            data["STATUS"],
                                            className="text-white uppercase text-xs font-bold rounded-lg px-2 py-1",
                                            style={
                                                "background-color": color_mapping_status[
                                                    data["STATUS"]
                                                ],
                                            },
                                        ),
                                    ],
                                    className="w-[9.5%] 2xl:w-[9%]",
                                    width=1,
                                ),
                                dbc.Col(
                                    [
                                        html.Span(
                                            data["REGION"],
                                            className="uppercase text-xs font-bold",
                                            style={
                                                "display": "flex",
                                                "align-items": "center",
                                            },
                                        ),
                                    ],
                                    className="w-[10.5%] 2xl:w-[10%]",
                                    width=1,
                                ),
                                dbc.Col(
                                    [
                                        html.Span(
                                            data["SERVICE_NAME"],
                                            className="uppercase text-xs font-bold",
                                            style={
                                                "display": "flex",
                                                "align-items": "center",
                                            },
                                        ),
                                    ],
                                    className="w-[14.5%] 2xl:w-[10%]",
                                    width=1,
                                ),
                                dbc.Col(
                                    [
                                        html.Span(
                                            data["ACCOUNT_UID"],
                                            className="uppercase text-xs font-bold",
                                            style={
                                                "display": "flex",
                                                "align-items": "center",
                                            },
                                        ),
                                    ],
                                    className="w-[14.5%] 2xl:w-[10%]",
                                    width=2,
                                ),
                            ],
                            align="center",
                            className="g-0",
                        ),
                    ),
                    dbc.Collapse(
                        dbc.CardBody(
                            [
                                html.H5(
                                    "Details",
                                    className="card-title",
                                    style={"font-weight": "bold"},
                                ),
                                html.Div(
                                    [
                                        html.Div(
                                            [
                                                # Description as first details item
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Description: ",
                                                                style={
                                                                    "margin-bottom": "8px"
                                                                },
                                                            )
                                                        ),
                                                        html.Div(
                                                            dcc.Markdown(
                                                                str(
                                                                    data.get(
                                                                        "DESCRIPTION",
                                                                        "",
                                                                    )
                                                                ),
                                                                dangerously_allow_html=True,
                                                                style={
                                                                    "margin-left": "0px",
                                                                    "padding-left": "10px",
                                                                },
                                                            ),
                                                            className="markdown-content",
                                                            style={
                                                                "margin-left": "0px",
                                                                "padding-left": "10px",
                                                            },
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "ResourceUid: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "RESOURCE_UID", ""
                                                                )
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "FindingUid: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "FINDING_UID", ""
                                                                )
                                                            ),
                                                            style={
                                                                "margin-left": "5px"
                                                            },
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "CheckId: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get("CHECK_ID", "")
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Type: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "RESOURCE_TYPE", ""
                                                                )
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Details: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "RESOURCE_DETAILS",
                                                                    "",
                                                                )
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "StatusExtended: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "STATUS_EXTENDED",
                                                                    "",
                                                                )
                                                            ),
                                                            style={
                                                                "margin-left": "5px"
                                                            },
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                            ],
                                            style={
                                                "width": "50%",
                                                "display": "inline-block",
                                            },
                                        ),
                                        html.Div(
                                            [
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Risk: ",
                                                                style={},
                                                            )
                                                        ),
                                                        html.Div(
                                                            dcc.Markdown(
                                                                str(
                                                                    data.get("RISK", "")
                                                                ),
                                                                dangerously_allow_html=True,
                                                                style={
                                                                    "margin-left": "0px",
                                                                    "padding-left": "10px",
                                                                },
                                                            ),
                                                            className="markdown-content",
                                                            style={
                                                                "margin-left": "0px",
                                                                "padding-left": "10px",
                                                            },
                                                        ),
                                                    ],
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Notes: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(data.get("NOTES", ""))
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Provider: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get("PROVIDER", "")
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Recommendation: ",
                                                                style={
                                                                    "margin-bottom": "8px"
                                                                },
                                                            )
                                                        ),
                                                        html.Div(
                                                            dcc.Markdown(
                                                                str(
                                                                    data.get(
                                                                        "REMEDIATION_RECOMMENDATION_TEXT",
                                                                        "",
                                                                    )
                                                                ),
                                                                dangerously_allow_html=True,
                                                                style={
                                                                    "margin-left": "0px",
                                                                    "padding-left": "10px",
                                                                },
                                                            ),
                                                            className="markdown-content",
                                                            style={
                                                                "margin-left": "0px",
                                                                "padding-left": "10px",
                                                            },
                                                        ),
                                                    ],
                                                    style={"margin-bottom": "15px"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "RecommendationUrl: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.A(
                                                            str(
                                                                data.get(
                                                                    "REMEDIATION_RECOMMENDATION_URL",
                                                                    "",
                                                                )
                                                            ),
                                                            href=str(
                                                                data.get(
                                                                    "REMEDIATION_RECOMMENDATION_URL",
                                                                    "",
                                                                )
                                                            ),
                                                            style={
                                                                "color": "#3182ce",
                                                                "margin-left": "5px",
                                                            },
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                                html.Div(
                                                    [
                                                        html.P(
                                                            html.Strong(
                                                                "Scan Day: ",
                                                                style={
                                                                    "margin-right": "5px"
                                                                },
                                                            )
                                                        ),
                                                        html.P(
                                                            str(
                                                                data.get(
                                                                    "ASSESSMENT_TIME",
                                                                    "",
                                                                )
                                                            )
                                                        ),
                                                    ],
                                                    style={"display": "flex"},
                                                ),
                                            ],
                                            style={
                                                "width": "50%",
                                                "display": "inline-block",
                                            },
                                        ),
                                    ],
                                    style={"display": "flex", "width": "100%"},
                                ),
                            ]
                        ),
                        id={"type": "collapse", "index": index},
                        is_open=False,
                    ),
                ]
            )
        ]
    )
