import re

import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from dash import dash_table, dcc, html

from dashboard.config import fail_emoji, info_emoji, manual_emoji, pass_emoji


def version_tuple(version):
    version = re.sub("[a-zA-Z]", "", version)
    if version == "" or version == "-" or version == " " or version == "_":
        return version
    else:
        if "." in version:
            delimiter = "."
        elif "-" in version:
            delimiter = "-"
        elif "_" in version:
            delimiter = "_"
        else:
            delimiter = None

        # clean up all the strings that end with . or - or _ (few cases)
        while version[-1] == ".":
            version = version.replace(".", "", 1)

        while version[-1] == "-":
            version = version.replace("-", "", 1)

        while version[-1] == "_":
            version = version.replace("_", "", 1)

        if delimiter:
            return tuple(
                int(segment) for segment in version.split(delimiter) if segment
            )
        else:
            return version


def map_status_to_icon(status):
    if status == "FAIL":
        return fail_emoji
    elif status == "PASS":
        return pass_emoji
    elif status == "INFO":
        return info_emoji
    elif status == "MANUAL":
        return manual_emoji
    return status


def get_section_containers_cis(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data.sort_values(by=section_1, key=lambda x: x.map(version_tuple), inplace=True)
    data[section_1] = data[section_1].astype(str)
    data.drop_duplicates(keep="first", inplace=True)

    findings_counts_section = (
        data.groupby([section_2, "STATUS"]).size().unstack(fill_value=0)
    )
    findings_counts_id = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for section in data[section_2].unique():
        success_section = (
            findings_counts_section.loc[section, pass_emoji]
            if pass_emoji in findings_counts_section.columns
            else 0
        )
        failed_section = (
            findings_counts_section.loc[section, fail_emoji]
            if fail_emoji in findings_counts_section.columns
            else 0
        )

        fig_section = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
                ),
            ]
        )

        fig_section.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_section + failed_section,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_section),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_section),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_section.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_section.add_annotation(
            x=failed_section,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_section = dcc.Graph(
            figure=fig_section, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_section, className="graph-section")

        direct_internal_items = []
        for req_id in data[data[section_2] == section][section_1].unique():
            specific_data = data[
                (data[section_2] == section) & (data[section_1] == req_id)
            ]
            success_req = (
                findings_counts_id.loc[req_id, pass_emoji]
                if pass_emoji in findings_counts_id.columns
                else 0
            )
            failed_req = (
                findings_counts_id.loc[req_id, fail_emoji]
                if fail_emoji in findings_counts_id.columns
                else 0
            )

            # Create the DataTable for req_id
            data_table = dash_table.DataTable(
                data=specific_data.to_dict("records"),
                columns=[
                    {"name": i, "id": i}
                    for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
                ],
                style_table={"overflowX": "auto"},
                style_as_list_view=True,
                style_cell={"textAlign": "left", "padding": "5px"},
            )

            # Create the graph for req_id
            fig_req = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_req.update_layout(
                barmode="stack",
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                width=350,
                height=30,
                xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                annotations=[
                    dict(
                        x=success_req + failed_req,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_req),
                        showarrow=False,
                        font=dict(color="#1FB53F", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_req),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_req.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_req.add_annotation(
                x=failed_req,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_req = dcc.Graph(
                figure=fig_req, config={"staticPlot": True}, className="info-bar-child"
            )

            graph_div_req = html.Div(graph_req, className="graph-section-req")

            title_internal = (
                f"{req_id} - {specific_data['REQUIREMENTS_DESCRIPTION'].iloc[0]}"
            )

            # Cut the title if it's too long
            title_internal = (
                title_internal[:130] + " ..."
                if len(title_internal) > 130
                else title_internal
            )

            internal_accordion_item = dbc.AccordionItem(
                title=title_internal,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_section_container = html.Div(
                [
                    graph_div_req,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_section_container)

        accordion_item = dbc.AccordionItem(
            title=f"{section}", children=direct_internal_items
        )
        section_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(section_container)

    return html.Div(section_containers, className="compliance-data-layout")


def get_section_containers_format1(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data.sort_values(by=section_2, key=lambda x: x.map(version_tuple), inplace=True)
    data[section_2] = data[section_2].astype(str)
    data.drop_duplicates(keep="first", inplace=True)

    findings_counts_section = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )
    findings_counts_id = (
        data.groupby([section_2, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for section in data[section_1].unique():
        success_section = (
            findings_counts_section.loc[section, pass_emoji]
            if pass_emoji in findings_counts_section.columns
            else 0
        )
        failed_section = (
            findings_counts_section.loc[section, fail_emoji]
            if fail_emoji in findings_counts_section.columns
            else 0
        )

        fig_section = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
                ),
            ]
        )

        fig_section.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_section + failed_section,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_section),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_section),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_section.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_section.add_annotation(
            x=failed_section,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_section = dcc.Graph(
            figure=fig_section, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_section, className="graph-section")

        direct_internal_items = []
        for req_id in data[data[section_1] == section][section_2].unique():
            specific_data = data[
                (data[section_1] == section) & (data[section_2] == req_id)
            ]
            success_req = (
                findings_counts_id.loc[req_id, pass_emoji]
                if pass_emoji in findings_counts_id.columns
                else 0
            )
            failed_req = (
                findings_counts_id.loc[req_id, fail_emoji]
                if fail_emoji in findings_counts_id.columns
                else 0
            )

            # Create the DataTable for req_id
            data_table = dash_table.DataTable(
                data=specific_data.to_dict("records"),
                columns=[
                    {"name": i, "id": i}
                    for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
                ],
                style_table={"overflowX": "auto"},
                style_as_list_view=True,
                style_cell={"textAlign": "left", "padding": "5px"},
            )

            # Create the graph for req_id
            fig_req = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_req.update_layout(
                barmode="stack",
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                width=350,
                height=30,
                xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                annotations=[
                    dict(
                        x=success_req + failed_req,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_req),
                        showarrow=False,
                        font=dict(color="#1FB53F", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_req),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_req.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_req.add_annotation(
                x=failed_req,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_req = dcc.Graph(
                figure=fig_req, config={"staticPlot": True}, className="info-bar-child"
            )

            graph_div_req = html.Div(graph_req, className="graph-section-req")

            internal_accordion_item = dbc.AccordionItem(
                title=req_id,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_section_container = html.Div(
                [
                    graph_div_req,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_section_container)

        accordion_item = dbc.AccordionItem(
            title=f"{section}", children=direct_internal_items
        )
        section_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(section_container)

    return html.Div(section_containers, className="compliance-data-layout")


def get_section_containers_format2(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data.drop_duplicates(keep="first", inplace=True)
    findings_counts_section = (
        data.groupby([section_2, "STATUS"]).size().unstack(fill_value=0)
    )
    findings_counts_name = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for name in data[section_1].unique():
        success_name = (
            findings_counts_name.loc[name, pass_emoji]
            if pass_emoji in findings_counts_name.columns
            else 0
        )
        failed_name = (
            findings_counts_name.loc[name, fail_emoji]
            if fail_emoji in findings_counts_name.columns
            else 0
        )

        fig_name = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_name],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_name],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
                ),
            ]
        )

        fig_name.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_name + failed_name,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_name),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_name),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_name.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_name.add_annotation(
            x=failed_name,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_name = dcc.Graph(
            figure=fig_name, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_name, className="graph-section")

        direct_internal_items = []
        for section in data[data[section_1] == name][section_2].unique():
            specific_data = data[
                (data[section_1] == name) & (data[section_2] == section)
            ]
            success_section = (
                findings_counts_section.loc[section, pass_emoji]
                if pass_emoji in findings_counts_section.columns
                else 0
            )
            failed_section = (
                findings_counts_section.loc[section, fail_emoji]
                if fail_emoji in findings_counts_section.columns
                else 0
            )

            # Create the DataTable for req_id
            data_table = dash_table.DataTable(
                data=specific_data.to_dict("records"),
                columns=[
                    {"name": i, "id": i}
                    for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
                ],
                style_table={"overflowX": "auto"},
                style_as_list_view=True,
                style_cell={"textAlign": "left", "padding": "5px"},
            )
            # Create the graph for req_id
            fig_section = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_section],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_section],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_section.update_layout(
                barmode="stack",
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                width=350,
                height=30,
                xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                annotations=[
                    dict(
                        x=success_section + failed_section,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_section),
                        showarrow=False,
                        font=dict(color="#1FB53F", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_section),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_section.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_section.add_annotation(
                x=failed_section,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_section = dcc.Graph(
                figure=fig_section,
                config={"staticPlot": True},
                className="info-bar-child",
            )

            graph_div_section = html.Div(graph_section, className="graph-section-req")

            internal_accordion_item = dbc.AccordionItem(
                title=section,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_section_container = html.Div(
                [
                    graph_div_section,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_section_container)

        accordion_item = dbc.AccordionItem(
            title=f"{name}", children=direct_internal_items
        )
        section_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(section_container)

    return html.Div(section_containers, className="compliance-data-layout")


def get_section_containers_format3(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data.sort_values(by=section_2, key=lambda x: x.map(version_tuple), inplace=True)
    data[section_2] = data[section_2].astype(str)
    data.drop_duplicates(keep="first", inplace=True)

    findings_counts_section = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )
    findings_counts_id = (
        data.groupby([section_2, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for section in data[section_1].unique():
        success_section = (
            findings_counts_section.loc[section, pass_emoji]
            if pass_emoji in findings_counts_section.columns
            else 0
        )
        failed_section = (
            findings_counts_section.loc[section, fail_emoji]
            if fail_emoji in findings_counts_section.columns
            else 0
        )

        fig_section = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
                ),
            ]
        )

        fig_section.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_section + failed_section,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_section),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_section),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_section.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_section.add_annotation(
            x=failed_section,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_section = dcc.Graph(
            figure=fig_section, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_section, className="graph-section")

        direct_internal_items = []
        for req_id in data[data[section_1] == section][section_2].unique():
            specific_data = data[
                (data[section_1] == section) & (data[section_2] == req_id)
            ]
            success_req = (
                findings_counts_id.loc[req_id, pass_emoji]
                if pass_emoji in findings_counts_id.columns
                else 0
            )
            failed_req = (
                findings_counts_id.loc[req_id, fail_emoji]
                if fail_emoji in findings_counts_id.columns
                else 0
            )

            # Create the DataTable for req_id
            data_table = dash_table.DataTable(
                data=specific_data.to_dict("records"),
                columns=[
                    {"name": i, "id": i}
                    for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
                ],
                style_table={"overflowX": "auto"},
                style_as_list_view=True,
                style_cell={"textAlign": "left", "padding": "5px"},
            )

            # Create the graph for req_id
            fig_req = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_req.update_layout(
                barmode="stack",
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                width=350,
                height=30,
                xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                annotations=[
                    dict(
                        x=success_req + failed_req,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_req),
                        showarrow=False,
                        font=dict(color="#1FB53F", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_req),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_req.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_req.add_annotation(
                x=failed_req,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_req = dcc.Graph(
                figure=fig_req, config={"staticPlot": True}, className="info-bar-child"
            )

            graph_div_req = html.Div(graph_req, className="graph-section-req")

            title_internal = (
                f"{req_id} - {specific_data['REQUIREMENTS_DESCRIPTION'].iloc[0]}"
            )
            # Cut the title if it's too long
            title_internal = (
                title_internal[:130] + " ..."
                if len(title_internal) > 130
                else title_internal
            )

            internal_accordion_item = dbc.AccordionItem(
                title=title_internal,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_section_container = html.Div(
                [
                    graph_div_req,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_section_container)

        tittle_external = (
            f"{section} - {specific_data['REQUIREMENTS_DESCRIPTION'].iloc[0]}"
        )
        # Cut the title if it's too long
        tittle_external = (
            tittle_external[:70] + " ..."
            if len(tittle_external) > 70
            else tittle_external
        )
        accordion_item = dbc.AccordionItem(
            title=f"{tittle_external}", children=direct_internal_items
        )
        section_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(section_container)

    return html.Div(section_containers, className="compliance-data-layout")


def get_section_containers_rbi(data, section_1):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data[section_1] = data[section_1].astype(str)
    data.drop_duplicates(keep="first", inplace=True)
    findings_counts_id = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    direct_internal_items = []
    for req_id in data[section_1].unique():
        specific_data = data[data[section_1] == req_id]
        success_req = (
            findings_counts_id.loc[req_id, pass_emoji]
            if pass_emoji in findings_counts_id.columns
            else 0
        )
        failed_req = (
            findings_counts_id.loc[req_id, fail_emoji]
            if fail_emoji in findings_counts_id.columns
            else 0
        )

        # Create the DataTable for req_id
        data_table = dash_table.DataTable(
            data=specific_data.to_dict("records"),
            columns=[
                {"name": i, "id": i}
                for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
            ],
            style_table={"overflowX": "auto"},
            style_as_list_view=True,
            style_cell={"textAlign": "left", "padding": "5px"},
        )

        # Create the graph for req_id
        fig_req = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_req],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                ),
                go.Bar(
                    name="Success",
                    x=[success_req],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                ),
            ]
        )

        fig_req.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_req + failed_req,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_req),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_req),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_req.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_req.add_annotation(
            x=failed_req,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_req = dcc.Graph(
            figure=fig_req, config={"staticPlot": True}, className="info-bar-child"
        )

        graph_div_req = html.Div(graph_req, className="graph-section-req")

        title_internal = (
            f"{req_id} - {specific_data['REQUIREMENTS_DESCRIPTION'].iloc[0]}"
        )
        # Cut the title if it's too long
        title_internal = (
            title_internal[:70] + " ..." if len(title_internal) > 70 else title_internal
        )

        internal_accordion_item = dbc.AccordionItem(
            title=title_internal,
            children=[html.Div([data_table], className="inner-accordion-content")],
        )

        internal_section_container = html.Div(
            [
                graph_div_req,
                dbc.Accordion(
                    [internal_accordion_item], start_collapsed=True, flush=True
                ),
            ],
            className="accordion-inner",
        )

        direct_internal_items.append(internal_section_container)

    return html.Div(direct_internal_items, className="compliance-data-layout")


def get_section_container_iso(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data.drop_duplicates(keep="first", inplace=True)
    data.sort_values(
        by=section_1,
        key=lambda x: x.map(version_tuple),
        inplace=True,
    )
    data.sort_values(
        by=section_2,
        key=lambda x: x.map(version_tuple),
        inplace=True,
    )
    findings_counts_objetive_id = (
        data.groupby([section_2, "STATUS"]).size().unstack(fill_value=0)
    )
    findings_counts_category = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for category in data[section_1].unique():
        success_category = (
            findings_counts_category.loc[category, pass_emoji]
            if pass_emoji in findings_counts_category.columns
            else 0
        )
        failed_category = (
            findings_counts_category.loc[category, fail_emoji]
            if fail_emoji in findings_counts_category.columns
            else 0
        )

        fig_category = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_category],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_category],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
                ),
            ]
        )

        fig_category.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_category + failed_category,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_category),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_category),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_category.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_category.add_annotation(
            x=failed_category,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_category = dcc.Graph(
            figure=fig_category, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_category, className="graph-section")

        direct_internal_items = []
        for objetive_id in data[data[section_1] == category][section_2].unique():
            specific_data = data[
                (data[section_1] == category) & (data[section_2] == objetive_id)
            ]
            success_objetive_id = (
                findings_counts_objetive_id.loc[objetive_id, pass_emoji]
                if pass_emoji in findings_counts_objetive_id.columns
                else 0
            )
            failed_objetive_id = (
                findings_counts_objetive_id.loc[objetive_id, fail_emoji]
                if fail_emoji in findings_counts_objetive_id.columns
                else 0
            )

            # Create the DataTable for req_id
            data_table = dash_table.DataTable(
                data=specific_data.to_dict("records"),
                columns=[
                    {"name": i, "id": i}
                    for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
                ],
                style_table={"overflowX": "auto"},
                style_as_list_view=True,
                style_cell={"textAlign": "left", "padding": "5px"},
            )
            # Create the graph for req_id
            fig_objetive_id = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_objetive_id],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_objetive_id],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_objetive_id.update_layout(
                barmode="stack",
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                width=350,
                height=30,
                xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
                annotations=[
                    dict(
                        x=success_objetive_id + failed_objetive_id,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_objetive_id),
                        showarrow=False,
                        font=dict(color="#1FB53F", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_objetive_id),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_objetive_id.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_objetive_id.add_annotation(
                x=failed_objetive_id,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_objetive_id = dcc.Graph(
                figure=fig_objetive_id,
                config={"staticPlot": True},
                className="info-bar-child",
            )

            graph_div_objetive_id = html.Div(
                graph_objetive_id, className="graph-section-req"
            )

            title_internal = f"{objetive_id} - {specific_data['REQUIREMENTS_ATTRIBUTES_OBJETIVE_NAME'].iloc[0]}"
            # Cut the title if it's too long
            title_internal = (
                title_internal[:130] + " ..."
                if len(title_internal) > 130
                else title_internal
            )

            internal_accordion_item = dbc.AccordionItem(
                title=title_internal,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_objetive_id_container = html.Div(
                [
                    graph_div_objetive_id,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_objetive_id_container)

        accordion_item = dbc.AccordionItem(
            title=f"{category}", children=direct_internal_items
        )
        objetive_id_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(objetive_id_container)

    return html.Div(section_containers, className="compliance-data-layout")


def get_section_containers_pci(data, section_1):

    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data[section_1] = data[section_1].astype(str)
    data.drop_duplicates(keep="first", inplace=True)
    findings_counts_service = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    direct_internal_items = []
    for service in data[section_1].unique():
        specific_data = data[data[section_1] == service]
        success_service = (
            findings_counts_service.loc[service, pass_emoji]
            if pass_emoji in findings_counts_service.columns
            else 0
        )
        failed_service = (
            findings_counts_service.loc[service, fail_emoji]
            if fail_emoji in findings_counts_service.columns
            else 0
        )

        # Create the DataTable for service
        data_table = dash_table.DataTable(
            data=specific_data.to_dict("records"),
            columns=[
                {"name": i, "id": i}
                for i in ["CHECKID", "STATUS", "REGION", "ACCOUNTID", "RESOURCEID"]
            ],
            style_table={"overflowX": "auto"},
            style_as_list_view=True,
            style_cell={"textAlign": "left", "padding": "5px"},
        )

        # Create the graph for service
        fig_service = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_service],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                ),
                go.Bar(
                    name="Success",
                    x=[success_service],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                ),
            ]
        )

        fig_service.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            width=350,
            height=30,
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_service + failed_service,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_service),
                    showarrow=False,
                    font=dict(color="#1FB53F", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_service),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
        )

        fig_service.add_annotation(
            x=50,
            y=0,
            text="",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
        )

        fig_service.add_annotation(
            x=failed_service,
            y=0.3,
            text="|",
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            textangle=0,
            font=dict(size=20),
        )

        graph_service = dcc.Graph(
            figure=fig_service, config={"staticPlot": True}, className="info-bar-child"
        )

        graph_div_service = html.Div(graph_service, className="graph-section-req")

        internal_accordion_item = dbc.AccordionItem(
            title=service,
            children=[html.Div([data_table], className="inner-accordion-content")],
        )

        internal_section_container = html.Div(
            [
                graph_div_service,
                dbc.Accordion(
                    [internal_accordion_item], start_collapsed=True, flush=True
                ),
            ],
            className="accordion-inner",
        )

        direct_internal_items.append(internal_section_container)

    return html.Div(direct_internal_items, className="compliance-data-layout")
