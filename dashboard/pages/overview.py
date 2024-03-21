# Standard library imports
import csv
import glob
import os
import warnings
from datetime import datetime, timedelta
from itertools import product

# Third-party imports
import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import callback, ctx, dcc, html
from dash.dependencies import Input, Output

# Config import
from dashboard.config import folder_path_overview
from dashboard.lib.cards import create_provider_card
from dashboard.lib.dropdowns import (
    create_account_dropdown,
    create_date_dropdown,
    create_region_dropdown,
)
from dashboard.lib.layouts import create_layout_overview

# Suppress warnings
warnings.filterwarnings("ignore")

# Global variables
# TODO: Create a flag to let the user put a custom path
csv_files = []

for file in glob.glob(os.path.join(folder_path_overview, "*.csv")):
    with open(file, "r", newline="") as csvfile:
        reader = csv.reader(csvfile)
        num_rows = sum(1 for row in reader)
        if num_rows > 1:
            csv_files.append(file)


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


def load_csv_files(csv_files):
    """Load CSV files into a single pandas DataFrame."""
    dfs = []
    for file in csv_files:
        df = pd.read_csv(file, sep=";", on_bad_lines="skip")
        if "CHECK_ID" in df.columns:
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
    # Fixing Date datatype
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])
    data["ASSESSMENT_TIME"] = data["TIMESTAMP"].dt.strftime("%Y-%m-%d %H:%M:%S")

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
    for account in data["ACCOUNT_NAME"].unique():
        if "azure" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
            accounts.append(account + " - AZURE")
        if "gcp" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
            accounts.append(account + " - GCP")

    for account in data["ACCOUNT_UID"].unique():
        if "aws" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
            accounts.append(account + " - AWS")
        if "kubernetes" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
            accounts.append(account + " - K8S")

    account_dropdown = create_account_dropdown(accounts)

    # Region Dropdown
    regions = ["All"] + list(data["REGION"].unique())
    region_dropdown = create_region_dropdown(regions)

    # Create the download button
    download_button = html.Button(
        "Download this table as CSV",
        id="download_link",
        n_clicks=0,
        className="border-solid border-2 border-prowler-stone-900/10 hover:border-solid hover:border-2 hover:border-prowler-stone-900/10 text-prowler-stone-900 inline-block px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 flex justify-end w-fit",
    )

    # Initializing the Dash App
    dash.register_page(__name__, path="/")

    # Create the layout
    layout = create_layout_overview(
        account_dropdown, date_dropdown, region_dropdown, download_button
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
        Output("subscribe_card", "children"),
        Output("info-file-over", "title"),
    ],
    Input("cloud-account-filter", "value"),
    Input("region-filter", "value"),
    Input("report-date-filter", "value"),
    Input("download_link", "n_clicks"),
)
def filter_data(
    cloud_account_values, region_account_values, assessment_value, n_clicks
):
    filtered_data = data.copy()

    # Take the latest date of de data
    account_date = data["ASSESSMENT_TIME"].unique()
    account_date.sort()
    account_date = account_date[::-1]

    start_date = datetime.strptime(account_date[0], "%Y-%m-%d") - timedelta(days=7)
    end_date = datetime.strptime(account_date[0], "%Y-%m-%d")

    filtered_data_sp = data[
        (data["TIMESTAMP"] >= start_date) & (data["TIMESTAMP"] <= end_date)
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
            df["TIMESTAMP"] = pd.to_datetime(df["TIMESTAMP"])
            df["TIMESTAMP"] = df["TIMESTAMP"].dt.strftime("%Y-%m-%d")
            if df["TIMESTAMP"][0].split(" ")[0] == updated_assessment_value:
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
    for account in filtered_data["ACCOUNT_UID"].unique():
        if "aws" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
            all_account_ids.append(account)
        if "kubernetes" in list(data[data["ACCOUNT_UID"] == account]["PROVIDER"]):
            all_account_ids.append(account)

    all_account_names = []
    for account in filtered_data["ACCOUNT_NAME"].unique():
        if "azure" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
            all_account_names.append(account)
        if "gcp" in list(data[data["ACCOUNT_NAME"] == account]["PROVIDER"]):
            all_account_names.append(account)

    all_items = all_account_ids + all_account_names + ["All"]

    cloud_accounts_options = ["All"]
    for item in all_items:
        if item not in cloud_accounts_options and item.__class__.__name__ == "str":
            # append the provider name depending on the account
            if "aws" in list(data[data["ACCOUNT_UID"] == item]["PROVIDER"]):
                cloud_accounts_options.append(item + " - AWS")
            elif "azure" in list(data[data["ACCOUNT_NAME"] == item]["PROVIDER"]):
                cloud_accounts_options.append(item + " - AZURE")
            elif "gcp" in list(data[data["ACCOUNT_NAME"] == item]["PROVIDER"]):
                cloud_accounts_options.append(item + " - GCP")
            elif "kubernetes" in list(data[data["ACCOUNT_UID"] == item]["PROVIDER"]):
                cloud_accounts_options.append(item + " - K8S")

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
    filtered_data = filtered_data[
        filtered_data["ACCOUNT_UID"].isin(values_choice)
        | filtered_data["ACCOUNT_NAME"].isin(values_choice)
    ]

    copy_data = filtered_data.copy()
    # Filter REGION
    # Check if filtered data contains an aws account
    # TODO - Handle azure locations
    if not filtered_data["PROVIDER"].str.contains("azure").any():
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

    region_filter_options = ["All"] + list(copy_data["REGION"].unique())

    # Select failed findings
    fails_findings = filtered_data[filtered_data["STATUS"] == "FAIL"]

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
            # Formating date columns
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
                "FAIL": "#FF7452",
                "PASS": "#36B37E",
                "INFO": "#2684FF",
                "WARN": "#260000",
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
        table = dcc.Graph(figure=fig, config={"displayModeBar": False})

    else:
        df = filtered_data.copy()

        # Status Pie Chart
        df1 = filtered_data[filtered_data["STATUS"] == "FAIL"]

        color_mapping_pass_fail = {
            "FAIL": "#FF7452",
            "PASS": "#36B37E",
            "INFO": "#2684FF",
            "MANUAL": "#8332A8",
        }
        # Define custom colors
        color_mapping = {
            "critical": "#800000",
            "high": "#FF5630",
            "medium": "#FF991F",
            "low": "#FFC400",
            "informational": "#3274d9",
        }

        # Use the color_discrete_map parameter to map categories to custom colors
        fig2 = px.pie(
            filtered_data,
            names="STATUS",
            hole=0.7,
            color="STATUS",
            color_discrete_map=color_mapping_pass_fail,
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

        # Figure for the bar chart

        color_bars = [
            color_mapping["critical"],
            color_mapping["high"],
            color_mapping["medium"],
            color_mapping["low"],
        ]

        figure_bars = go.Figure(
            data=[
                go.Bar(
                    x=df1["SEVERITY"]
                    .value_counts()
                    .index,  # assign x as the dataframe column 'x'
                    y=df1["SEVERITY"].value_counts().values,
                    marker=dict(color=color_bars),
                    textposition="auto",
                )
            ],
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
        severity_dict = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        fails_findings["SEVERITY"] = fails_findings["SEVERITY"].map(severity_dict)
        fails_findings = fails_findings.sort_values(by=["SEVERITY"], ascending=False)
        fails_findings["SEVERITY"] = fails_findings["SEVERITY"].replace(
            {3: "critical", 2: "high", 1: "medium", 0: "low"}
        )
        table_data = fails_findings.copy()
        # Append the value from the colum 'ACCOUNT_NAME' to the 'ACCOUNT_UID' column
        for subscription in table_data["ACCOUNT_NAME"].unique():
            table_data.loc[
                table_data["ACCOUNT_NAME"] == subscription, "ACCOUNT_UID"
            ] = subscription

        table_data["RISK"] = table_data["RISK"].str.slice(0, 50)
        table_data["CHECK_ID"] = (
            table_data["CHECK_ID"] + " - " + table_data["RESOURCE_UID"]
        )
        # if the region is empty, we are going to fill it with '-'
        table_data["REGION"] = table_data["REGION"].fillna("-")
        table_data = table_data[
            [
                "CHECK_ID",
                "SEVERITY",
                "STATUS",
                "REGION",
                "SERVICE_NAME",
                "PROVIDER",
                "ACCOUNT_UID",
            ]
        ]
        table_data = table_data.rename(
            columns={
                "CHECK_ID": "Check ID",
                "SEVERITY": "Severity",
                "STATUS": "Status",
                "REGION": "Region",
                "SERVICE_NAME": "Service",
                "PROVIDER": "Provider",
                "ACCOUNT_UID": "Account ID",
            }
        )

        if len(table_data) > 25:
            table = dbc.Table.from_dataframe(
                table_data[:25],
                striped=True,
                bordered=False,
                hover=True,
                className="table-overview",
            )
        else:
            table = dbc.Table.from_dataframe(
                table_data,
                striped=True,
                bordered=False,
                hover=True,
                className="table-overview",
            )

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
        html.Div([table], className="grid grid-cols-auto"),
    ]

    # Create Provider Cards
    aws_card = create_provider_card("aws", aws_provider_logo, "Accounts", filtered_data)
    azure_card = create_provider_card(
        "azure", azure_provider_logo, "Subscriptions", filtered_data
    )
    gcp_card = create_provider_card("gcp", gcp_provider_logo, "Projects", filtered_data)
    k8s_card = create_provider_card(
        "kubernetes", ks8_provider_logo, "Clusters", filtered_data
    )

    # Subscribe to prowler SaaS card
    subscribe_card = [
        html.Div(
            html.A(
                [
                    html.Img(src="assets/favicon.ico", className="w-5 mr-3"),
                    html.Span("Subscribe to prowler SaaS"),
                ],
                href="https://prowler.pro/",
                target="_blank",
                className="text-prowler-stone-900 inline-flex px-4 py-2 text-xs font-bold uppercase transition-all rounded-lg text-gray-900 hover:bg-prowler-stone-900/10 border-solid border-1 hover:border-prowler-stone-900/10 hover:border-solid hover:border-1 border-prowler-stone-900/10",
            ),
        )
    ]
    if ctx.triggered_id == "download_link":
        csv_data = dcc.send_data_frame(table_data[:25].to_csv, "mydf.csv")
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
            subscribe_card,
            list_files,
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
            subscribe_card,
            list_files,
        )
