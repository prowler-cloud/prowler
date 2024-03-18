# Importing Packages
import datetime
import glob
import os
import warnings
from itertools import product

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import callback, ctx, dcc, html
from dash.dependencies import Input, Output

warnings.filterwarnings("ignore")
from datetime import datetime, timedelta

import numpy as np

try:
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

    # Get the current working directory
    current_directory = os.getcwd()

    # TODO: Create a flag to let the user put a custom path
    # Specify the folder path (assuming "Data" is in the current directory)
    folder_path = f"{os.path.join(current_directory)}/../output"

    # Use glob to find all CSV files in the folder
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    csv_files = [file for file in csv_files]

    dfs = []
    # Loop through the list of CSV files and store in a single df, append only the files that contain the colum 'Check_ID' and read all like an string
    for file in csv_files:
        df = pd.read_csv(file, sep=";", on_bad_lines="skip")
        if "CHECK_ID" in df.columns:
            dfs.append(df.astype(str))

    # creating dataframe
    data = pd.concat(dfs, ignore_index=True)

    # Fixing Date datatype
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])
    data["ASSESSMENT_TIME"] = data["TIMESTAMP"].dt.strftime("%Y-%m-%d %H:%M:%S")

    data_valid = pd.DataFrame()
    if data["PROVIDER"].str.contains("aws").any():
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

    if data["PROVIDER"].str.contains("azure").any():
        for subscription in data["ACCOUNT_NAME"].unique():
            all_times = data[data["ACCOUNT_NAME"] == subscription][
                "ASSESSMENT_TIME"
            ].unique()
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
                        (data["ACCOUNT_NAME"] == subscription)
                        & (data["ASSESSMENT_TIME"].isin(times))
                    ],
                ]
            )

    if data["PROVIDER"].str.contains("gcp").any():
        for project in data["ACCOUNT_NAME"].unique():
            all_times = data[data["ACCOUNT_NAME"] == project][
                "ASSESSMENT_TIME"
            ].unique()
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
                        (data["ACCOUNT_NAME"] == project)
                        & (data["ASSESSMENT_TIME"].isin(times))
                    ],
                ]
            )

    if data["PROVIDER"].str.contains("kubernetes").any():
        for context in data["ACCOUNT_UID"].unique():
            all_times = data[data["ACCOUNT_UID"] == context]["ASSESSMENT_TIME"].unique()
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
                        (data["ACCOUNT_UID"] == context)
                        & (data["ASSESSMENT_TIME"].isin(times))
                    ],
                ]
            )

    data = data_valid
    # Select only the day in the data
    data["ASSESSMENT_TIME"] = data["ASSESSMENT_TIME"].apply(lambda x: x.split(" ")[0])

    data["TIMESTAMP"] = data["TIMESTAMP"].dt.strftime("%Y-%m-%d")
    data["TIMESTAMP"] = pd.to_datetime(data["TIMESTAMP"])

    #############################################################################
    """
					Select Date - Dropdown
	"""
    #############################################################################

    # Dropdown all options
    select_assessment_date = list(data["ASSESSMENT_TIME"].unique())
    select_assessment_date.sort()
    select_assessment_date.reverse()

    # Get the value of the current selected date from the dropdown report-date-filter
    list_files = ""

    dropdown3 = html.Div(
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
                        title=list_files,
                    ),
                ],
                style={"display": "inline-flex"},
            ),
            dcc.Dropdown(
                id="report-date-filter",
                options=[
                    {"label": account, "value": account}
                    for account in select_assessment_date
                ],
                value=select_assessment_date[0],  # Initial selection is ALL
                clearable=False,
                multi=False,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )

    #############################################################################
    """
					Select Clound Account - Dropdown
	"""
    #############################################################################

    # Dropdown all options
    select_account_dropdown_list = ["All"]
    select_account_dropdown_list = (
        select_account_dropdown_list
        + list(data["ACCOUNT_UID"].unique())
        + list(data["ACCOUNT_NAME"].unique())
        + list(data["ACCOUNT_UID"].unique())
        + list(data["ACCOUNT_UID"].unique())
    )
    list_items = []
    # delete nan values
    for item in select_account_dropdown_list:
        if item.__class__.__name__ == "str":
            list_items.append(item)

    select_account_dropdown_list = list_items

    # for item in the list, we are adding the provider name depending on the account
    for i in range(len(select_account_dropdown_list)):
        if select_account_dropdown_list[i] in list(data["ACCOUNT_UID"].unique()):
            select_account_dropdown_list[i] = select_account_dropdown_list[i] + " - AWS"
        elif select_account_dropdown_list[i] in list(data["ACCOUNT_NAME"].unique()):
            select_account_dropdown_list[i] = (
                select_account_dropdown_list[i] + " - AZURE"
            )
        elif select_account_dropdown_list[i] in list(data["ACCOUNT_UID"].unique()):
            select_account_dropdown_list[i] = select_account_dropdown_list[i] + " - GCP"
        elif select_account_dropdown_list[i] in list(data["ACCOUNT_UID"].unique()):
            select_account_dropdown_list[i] = select_account_dropdown_list[i] + " - K8S"

    dropdown1 = html.Div(
        [
            html.Label(
                "Account / Subscription / Project / Cluster:",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="cloud-account-filter",
                options=[
                    {"label": account, "value": account}
                    for account in select_account_dropdown_list
                ],
                value=["All"],  # Initial selection is ALL
                style={"color": "#000000", "width": "100%"},
                multi=True,
                clearable=False,
            ),
        ],
    )

    #############################################################################
    """
					Select Region - Dropdown
	"""
    #############################################################################

    # Dropdown all options
    select_account_dropdown_list = ["All"]
    select_account_dropdown_list = (
        select_account_dropdown_list
        + list(data["REGION"].unique())
        + list(data["REGION"].unique())
        + list(data["REGION"].unique())
    )

    list_items = []
    # delete nan values
    for item in select_account_dropdown_list:
        if item.__class__.__name__ == "str":
            list_items.append(item)

    select_account_dropdown_list = list_items

    dropdown2 = html.Div(
        [
            html.Label(
                "Region / Location / Namespace:",
                className="text-prowler-stone-900 font-bold text-sm",
            ),
            dcc.Dropdown(
                id="region-filter",
                options=[
                    {"label": account, "value": account}
                    for account in select_account_dropdown_list
                ],
                value=["All"],  # Initial selection is ALL
                clearable=False,
                multi=True,
                style={"color": "#000000", "width": "100%"},
            ),
        ],
    )

    # Initializing the Dash App
    dash.register_page(__name__, path="/")

    #####################################################################
    """LAYOUT"""
    #####################################################################

    layout = html.Div(
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
                    html.Div([dropdown3], className=""),
                    html.Div([dropdown1], className=""),
                    html.Div([dropdown2], className=""),
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
        cloud_account_values, region_account_values, assessent_value, n_clicks
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
        if assessent_value in account_date:
            updated_assessent_value = assessent_value
        else:
            updated_assessent_value = account_date[0]
            assessent_value = account_date[0]
        filtered_data = filtered_data[
            filtered_data["ASSESSMENT_TIME"] == updated_assessent_value
        ]

        # Select the files in the list_files that have the same date as the selected date
        list_files = []
        for file in csv_files:
            df = pd.read_csv(file, sep=";", on_bad_lines="skip")
            if "CHECK_ID" in df.columns:
                df["TIMESTAMP"] = pd.to_datetime(df["TIMESTAMP"])
                df["TIMESTAMP"] = df["TIMESTAMP"].dt.strftime("%Y-%m-%d")
                if df["TIMESTAMP"][0].split(" ")[0] == updated_assessent_value:
                    list_files.append(file)

        # append all the names of the files
        files_names = []
        for file in list_files:
            files_names.append(file.split("/")[-1])

        list_files = ",\n".join(files_names)
        list_files = "Files Scanned:\n" + list_files

        # Change the account selector to the values that are allowed
        filtered_data = filtered_data[
            filtered_data["ASSESSMENT_TIME"] == updated_assessent_value
        ]
        all_accounts = filtered_data["ACCOUNT_UID"].unique()
        all_subscriptions = filtered_data["ACCOUNT_NAME"].unique()
        all_projects = filtered_data["ACCOUNT_UID"].unique()
        all_contexts = filtered_data["ACCOUNT_UID"].unique()
        all_items = np.concatenate(
            (all_accounts, all_subscriptions, all_projects, all_contexts)
        )

        cloud_accounts_options = []
        for item in all_items:
            if item not in cloud_accounts_options and item.__class__.__name__ == "str":
                # append the provider name depending on the account
                if item in list(filtered_data["ACCOUNT_UID"].unique()):
                    cloud_accounts_options.append(item + " - AWS")
                elif item in list(filtered_data["ACCOUNT_NAME"].unique()):
                    cloud_accounts_options.append(item + " - AZURE")
                elif item in list(filtered_data["ACCOUNT_UID"].unique()):
                    cloud_accounts_options.append(item + " - GCP")
                elif item in list(filtered_data["ACCOUNT_UID"].unique()):
                    cloud_accounts_options.append(item + " - K8S")

        cloud_accounts_options = ["All"] + cloud_accounts_options

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
            | filtered_data["ACCOUNT_UID"].isin(values_choice)
            | filtered_data["ACCOUNT_UID"].isin(values_choice)
        ]

        # For the gcp account, replace the Location column with the REGION column
        filtered_data["REGION"] = filtered_data["REGION"].fillna(
            filtered_data["REGION"]
        )
        filtered_data = filtered_data.drop(columns=["REGION"])
        # For the k8s account, replace the REGION column with the REGION column
        filtered_data["REGION"] = filtered_data["REGION"].fillna(
            filtered_data["REGION"]
        )
        filtered_data = filtered_data.drop(columns=["REGION"])

        # Filter REGION
        # Check if filtered data contains an aws account
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

        region_filter_options = ["All"] + list(filtered_data["REGION"].unique())

        # Select issues that are failed
        filtered_data_table = filtered_data[filtered_data["STATUS"] == "FAIL"]

        # Count of accounts and checks executed for each provider

        accounts_aws = len(
            filtered_data[filtered_data["PROVIDER"] == "aws"]["ACCOUNT_UID"].unique()
        )
        checks_executed_aws = len(
            filtered_data[filtered_data["PROVIDER"] == "aws"]["CHECK_ID"].unique()
        )
        failed_aws = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "aws")
                & (filtered_data["STATUS"] == "FAIL")
            ]
        )
        passed_aws = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "aws")
                & (filtered_data["STATUS"] == "PASS")
            ]
        )

        accounts_azure = len(
            filtered_data[filtered_data["PROVIDER"] == "azure"]["ACCOUNT_NAME"].unique()
        )
        checks_executed_azure = len(
            filtered_data[filtered_data["PROVIDER"] == "azure"]["CHECK_ID"].unique()
        )
        failed_azure = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "azure")
                & (filtered_data["STATUS"] == "FAIL")
            ]
        )
        passed_azure = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "azure")
                & (filtered_data["STATUS"] == "PASS")
            ]
        )

        accounts_gcp = len(
            filtered_data[filtered_data["PROVIDER"] == "gcp"]["ACCOUNT_UID"].unique()
        )
        checks_executed_gcp = len(
            filtered_data[filtered_data["PROVIDER"] == "gcp"]["CHECK_ID"].unique()
        )
        failed_gcp = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "gcp")
                & (filtered_data["STATUS"] == "FAIL")
            ]
        )
        passed_gcp = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "gcp")
                & (filtered_data["STATUS"] == "PASS")
            ]
        )

        accounts_k8s = len(
            filtered_data[filtered_data["PROVIDER"] == "kubernetes"][
                "ACCOUNT_UID"
            ].unique()
        )
        checks_executed_k8s = len(
            filtered_data[filtered_data["PROVIDER"] == "kubernetes"][
                "CHECK_ID"
            ].unique()
        )
        failed_k8s = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "kubernetes")
                & (filtered_data["STATUS"] == "FAIL")
            ]
        )
        passed_k8s = len(
            filtered_data[
                (filtered_data["PROVIDER"] == "kubernetes")
                & (filtered_data["STATUS"] == "PASS")
            ]
        )

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
            except:
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

            ########################################################
            """PIE CHARTS 1"""
            ########################################################

            # Define custom colors
            color_mapping = {
                "FAIL": "#FF7452",
                "PASS": "#36B37E",
                "INFO": "#2684FF",
                "WARN": "#260000",
            }

            # Use the color_discrete_map parameter to map categories to custom colors
            fig1 = px.pie(
                df,
                names="STATUS",
                hole=0,
                color="STATUS",
                color_discrete_map=color_mapping,
            )
            fig1.update_traces(
                hovertemplate=None,
                textposition="outside",
                textinfo="percent+label",
                rotation=50,
            )

            fig1.update_layout(
                margin=dict(l=0, r=0, t=0, b=0),
                autosize=True,
                showlegend=False,
                font=dict(size=17, color="#8a8d93"),
                hoverlabel=dict(font_size=14),
                paper_bgcolor="#FFF",
            )

            ########################################################
            """PIE CHARTS 2"""
            ########################################################
            df1 = filtered_data[filtered_data["STATUS"] == "FAIL"]

            color_mapping_pass_fail = {
                "FAIL": "#FF7452",
                "PASS": "#36B37E",
                "INFO": "#2684FF",
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
            colors = [
                color_mapping["critical"],
                color_mapping["high"],
                color_mapping["medium"],
                color_mapping["low"],
            ]

            ########################################################
            """PIE CHARTS 3"""
            ########################################################
            figure_bars = go.Figure(
                data=[
                    go.Bar(
                        x=df1["SEVERITY"]
                        .value_counts()
                        .index,  # assign x as the dataframe column 'x'
                        y=df1["SEVERITY"].value_counts().values,
                        marker=dict(color=colors),
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
            ########################################################
            """TABLE"""
            ########################################################

            # SORT BY SEVERITY
            severity_dict = {"critical": 3, "high": 2, "medium": 1, "low": 0}
            filtered_data_table["SEVERITY"] = filtered_data_table["SEVERITY"].map(
                severity_dict
            )
            filtered_data_table = filtered_data_table.sort_values(
                by=["SEVERITY"], ascending=False
            )
            filtered_data_table["SEVERITY"] = filtered_data_table["SEVERITY"].replace(
                {3: "critical", 2: "high", 1: "medium", 0: "low"}
            )
            table_data = filtered_data_table.copy()
            # Append the value from the colum 'ACCOUNT_NAME' to the 'ACCOUNT_UID' column
            for subscription in table_data["ACCOUNT_NAME"].unique():
                table_data.loc[
                    table_data["ACCOUNT_NAME"] == subscription, "ACCOUNT_UID"
                ] = subscription
            # Append the value from the colum 'ACCOUNT_UID' to the 'ACCOUNT_UID' column
            for project in table_data["ACCOUNT_UID"].unique():
                table_data.loc[table_data["ACCOUNT_UID"] == project, "ACCOUNT_UID"] = (
                    project
                )
            # Append the value from the colum 'ACCOUNT_UID' to the 'ACCOUNT_UID' column
            for context in table_data["ACCOUNT_UID"].unique():
                table_data.loc[table_data["ACCOUNT_UID"] == context, "ACCOUNT_UID"] = (
                    context
                )
            # Drop the columns that are not going to be displayed
            table_data = table_data.drop(columns=["ACCOUNT_NAME"])
            table_data = table_data.drop(columns=["ACCOUNT_UID"])
            table_data = table_data.drop(columns=["ACCOUNT_UID"])

            table_data["RISK"] = table_data["RISK"].str.slice(0, 50)
            table_data["CHECK_ID"] = (
                table_data["CHECK_ID"] + " - " + table_data["RESOURCE_ID"]
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

        #####################################################################
        """Status Graphic"""
        #####################################################################
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

        #####################################################################
        """Layout two pie charts"""
        #####################################################################
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

        #####################################################################
        """Layout Line PLOT"""
        #####################################################################

        line_plot = [
            html.Span(
                "Security Posture Evolution (last 7 days)",
                className="text-center text-prowler-stone-900 uppercase text-xs font-bold",
            ),
            html.Div([line_chart], className=""),
        ]

        #####################################################################
        """Table"""
        #####################################################################
        table_card = [
            html.Div([table], className="grid grid-cols-auto"),
        ]

        #####################################################################
        """AWS Card"""
        #####################################################################

        # Card de aws en la que se muestra AWS y la parte de abajo el numero de fails y pass en total
        aws_card = [
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                [aws_provider_logo], className="w-8"
                                            ),
                                        ],
                                        className="p-2 shadow-box-up rounded-full",
                                    ),
                                    html.H5(
                                        "AWS accounts",
                                        className="text-base font-semibold leading-snug tracking-normal text-gray-900",
                                    ),
                                ],
                                className="flex justify-between items-center mb-3",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Span(
                                                "Accounts",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                accounts_aws,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "Checks",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                checks_executed_aws,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "FAILED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        failed_aws,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-failed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down  rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "PASSED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        passed_aws,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-passed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                ],
                                className="grid gap-x-8 gap-y-4",
                            ),
                        ],
                        className="px-4 py-3",
                    ),
                ],
                className="relative flex flex-col bg-white shadow-provider rounded-xl w-full transition ease-in-out delay-100 hover:-translate-y-1 hover:scale-110 hover:z-50 hover:cursor-pointer",
            )
        ]

        #####################################################################
        """Azure Card"""
        #####################################################################
        # Card de azure en la que se muestra Azure y la parte de abajo el numero de fails y pass en total
        azure_card = [
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                [azure_provider_logo], className="w-8"
                                            ),
                                        ],
                                        className="p-2 shadow-box-up rounded-full",
                                    ),
                                    html.H5(
                                        "AZURE subscriptions",
                                        className="text-base font-semibold leading-snug tracking-normal text-gray-900",
                                    ),
                                ],
                                className="flex justify-between items-center mb-3",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Span(
                                                "Subscriptions",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                accounts_azure,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "Checks",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                checks_executed_azure,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "FAILED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        failed_azure,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-failed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "PASSED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        passed_azure,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-passed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                ],
                                className="grid gap-x-8 gap-y-4",
                            ),
                        ],
                        className="px-4 py-3",
                    ),
                ],
                className="relative flex flex-col bg-white shadow-provider rounded-xl w-full transition ease-in-out delay-100 hover:-translate-y-1 hover:scale-110 hover:z-50 hover:cursor-pointer",
            )
        ]

        #####################################################################
        """GCP Card"""
        #####################################################################
        # Card de gcp en la que se muestra GCP y la parte de abajo el numero de fails y pass en total
        gcp_card = [
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                [gcp_provider_logo], className="w-8"
                                            ),
                                        ],
                                        className="p-2 shadow-box-up rounded-full",
                                    ),
                                    html.H5(
                                        "GCP projects",
                                        className="text-base font-semibold leading-snug tracking-normal text-gray-900",
                                    ),
                                ],
                                className="flex justify-between items-center mb-3",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Span(
                                                "Projects",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                accounts_gcp,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "Checks",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                checks_executed_gcp,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "FAILED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        failed_gcp,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-failed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "PASSED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        passed_gcp,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-passed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                ],
                                className="grid gap-x-8 gap-y-4",
                            ),
                        ],
                        className="px-4 py-3",
                    ),
                ],
                className="relative flex flex-col bg-white shadow-provider rounded-xl w-full transition ease-in-out delay-100 hover:-translate-y-1 hover:scale-110 hover:z-50 hover:cursor-pointer",
            )
        ]

        #####################################################################
        """K8S Card"""
        #####################################################################
        # Card de k8s en la que se muestra K8S y la parte de abajo el numero de fails y pass en total
        k8s_card = [
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                [ks8_provider_logo], className="w-8"
                                            ),
                                        ],
                                        className="p-2 shadow-box-up rounded-full",
                                    ),
                                    html.H5(
                                        "K8s clusters",
                                        className="text-base font-semibold leading-snug tracking-normal text-gray-900",
                                    ),
                                ],
                                className="flex justify-between items-center mb-3",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Span(
                                                "Clusters",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                accounts_k8s,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "Checks",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                checks_executed_k8s,
                                                className="inline-block text-xs  text-prowler-stone-900 font-bold shadow-box-down px-4 py-1 rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "FAILED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        failed_k8s,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-failed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down  rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                    html.Div(
                                        [
                                            html.Span(
                                                "PASSED",
                                                className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                            ),
                                            html.Div(
                                                [
                                                    html.Div(
                                                        passed_k8s,
                                                        className="m-[2px] px-4 py-1 rounded-lg bg-gradient-passed",
                                                    ),
                                                ],
                                                className="inline-block text-xs font-bold shadow-box-down rounded-lg text-center col-span-5 col-end-13",
                                            ),
                                        ],
                                        className="grid grid-cols-12",
                                    ),
                                ],
                                className="grid gap-x-8 gap-y-4",
                            ),
                        ],
                        className="px-4 py-3",
                    ),
                ],
                className="relative flex flex-col bg-white shadow-provider rounded-xl w-full transition ease-in-out delay-100 hover:-translate-y-1 hover:scale-110 hover:z-50 hover:cursor-pointer",
            )
        ]

        #####################################################################
        """Subscribe Card"""
        #####################################################################
        # Card de subscribe en la que se muestra el boton de subscribe
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
            csv_data = dcc.send_data_frame(table_data.to_csv, "mydf.csv")
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
                assessent_value,
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
                assessent_value,
                aws_card,
                azure_card,
                gcp_card,
                k8s_card,
                subscribe_card,
                list_files,
            )

except Exception as e:
    print(e)
