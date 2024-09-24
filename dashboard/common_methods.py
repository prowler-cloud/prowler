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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_name],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_section],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_section],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
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
                    marker=dict(color="#e77676"),
                ),
                go.Bar(
                    name="Success",
                    x=[success_req],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_category],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_objetive_id],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
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


def get_section_containers_format4(data, section_1):

    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data[section_1] = data[section_1].astype(str)

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
                    marker=dict(color="#e77676"),
                ),
                go.Bar(
                    name="Success",
                    x=[success_service],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
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
        if "REQUIREMENTS_NAME" not in specific_data.columns:
            title_internal = f"{service}"
        else:
            title_internal = f"{service} - {specific_data['REQUIREMENTS_NAME'].iloc[0]}"

        internal_accordion_item = dbc.AccordionItem(
            title=title_internal,
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


def get_section_containers_ens(data, section_1, section_2, section_3, section_4):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)

    findings_counts_marco = (
        data.groupby([section_1, "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for marco in data[section_1].unique():
        success_marco = (
            findings_counts_marco.loc[marco, pass_emoji]
            if pass_emoji in findings_counts_marco.columns
            else 0
        )
        failed_marco = (
            findings_counts_marco.loc[marco, fail_emoji]
            if fail_emoji in findings_counts_marco.columns
            else 0
        )

        fig_name = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_marco],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_marco],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    x=success_marco + failed_marco,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_marco),
                    showarrow=False,
                    font=dict(color="#45cc6e", size=14),
                    xanchor="left",
                    yanchor="middle",
                ),
                dict(
                    x=0,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(failed_marco),
                    showarrow=False,
                    font=dict(color="#e77676", size=14),
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
            x=failed_marco,
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

        for categoria in data[data[section_1] == marco][section_2].unique():
            specific_data = data[
                (data[section_1] == marco) & (data[section_2] == categoria)
            ]

            findings_counts_categoria = (
                specific_data.groupby([section_2, "STATUS"])
                .size()
                .unstack(fill_value=0)
            )

            success_categoria = (
                findings_counts_categoria.loc[categoria, pass_emoji]
                if pass_emoji in findings_counts_categoria.columns
                else 0
            )
            failed_categoria = (
                findings_counts_categoria.loc[categoria, fail_emoji]
                if fail_emoji in findings_counts_categoria.columns
                else 0
            )

            # Create the graph for req_id
            fig_section = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_categoria],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_categoria],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        x=success_categoria + failed_categoria,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_categoria),
                        showarrow=False,
                        font=dict(color="#45cc6e", size=14),
                        xanchor="left",
                        yanchor="middle",
                    ),
                    dict(
                        x=0,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(failed_categoria),
                        showarrow=False,
                        font=dict(color="#e77676", size=14),
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
                x=failed_categoria,
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

            direct_internal_items_idgrupocontrol = []

            for idgrupocontrol in specific_data[
                (specific_data[section_1] == marco)
                & (specific_data[section_2] == categoria)
            ][section_3].unique():
                specific_data2 = specific_data[
                    (specific_data[section_1] == marco)
                    & (specific_data[section_2] == categoria)
                    & (specific_data[section_3] == idgrupocontrol)
                ]

                findings_counts_idgrupocontrol = (
                    specific_data2.groupby([section_3, "STATUS"])
                    .size()
                    .unstack(fill_value=0)
                )

                success_idgrupocontrol = (
                    findings_counts_idgrupocontrol.loc[idgrupocontrol, pass_emoji]
                    if pass_emoji in findings_counts_idgrupocontrol.columns
                    else 0
                )
                failed_idgrupocontrol = (
                    findings_counts_idgrupocontrol.loc[idgrupocontrol, fail_emoji]
                    if fail_emoji in findings_counts_idgrupocontrol.columns
                    else 0
                )

                # Create the graph for req_id
                fig_idgrupocontrol = go.Figure(
                    data=[
                        go.Bar(
                            name="Failed",
                            x=[failed_idgrupocontrol],
                            y=[""],
                            orientation="h",
                            marker=dict(color="#e77676"),
                        ),
                        go.Bar(
                            name="Success",
                            x=[success_idgrupocontrol],
                            y=[""],
                            orientation="h",
                            marker=dict(color="#45cc6e"),
                        ),
                    ]
                )

                fig_idgrupocontrol.update_layout(
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
                            x=success_idgrupocontrol + failed_idgrupocontrol,
                            y=0,
                            xref="x",
                            yref="y",
                            text=str(success_idgrupocontrol),
                            showarrow=False,
                            font=dict(color="#45cc6e", size=14),
                            xanchor="left",
                            yanchor="middle",
                        ),
                        dict(
                            x=0,
                            y=0,
                            xref="x",
                            yref="y",
                            text=str(failed_idgrupocontrol),
                            showarrow=False,
                            font=dict(color="#e77676", size=14),
                            xanchor="right",
                            yanchor="middle",
                        ),
                    ],
                )

                fig_idgrupocontrol.add_annotation(
                    x=50,
                    y=0,
                    text="",
                    showarrow=False,
                    align="center",
                    xanchor="center",
                    yanchor="middle",
                    textangle=0,
                )

                fig_idgrupocontrol.add_annotation(
                    x=failed_idgrupocontrol,
                    y=0.3,
                    text="|",
                    showarrow=False,
                    align="center",
                    xanchor="center",
                    yanchor="middle",
                    textangle=0,
                    font=dict(size=20),
                )

                graph_idgrupocontrol = dcc.Graph(
                    figure=fig_idgrupocontrol,
                    config={"staticPlot": True},
                    className="info-bar-child",
                )

                graph_div_idgrupocontrol = html.Div(
                    graph_idgrupocontrol, className="graph-section-req"
                )

                direct_internal_items_tipo = []

                for tipo in specific_data2[
                    (specific_data2[section_1] == marco)
                    & (specific_data2[section_2] == categoria)
                    & (specific_data2[section_3] == idgrupocontrol)
                ][section_4].unique():
                    specific_data3 = specific_data2[
                        (specific_data2[section_1] == marco)
                        & (specific_data2[section_2] == categoria)
                        & (specific_data2[section_3] == idgrupocontrol)
                        & (specific_data2[section_4] == tipo)
                    ]

                    findings_counts_tipo = (
                        specific_data3.groupby([section_4, "STATUS"])
                        .size()
                        .unstack(fill_value=0)
                    )

                    success_tipo = (
                        findings_counts_tipo.loc[tipo, pass_emoji]
                        if pass_emoji in findings_counts_tipo.columns
                        else 0
                    )
                    failed_tipo = (
                        findings_counts_tipo.loc[tipo, fail_emoji]
                        if fail_emoji in findings_counts_tipo.columns
                        else 0
                    )

                    # Create the DataTable for each tipo
                    data_table = dash_table.DataTable(
                        data=specific_data3.to_dict("records"),
                        columns=[
                            {"name": i, "id": i}
                            for i in [
                                "CHECKID",
                                "STATUS",
                                "REGION",
                                "ACCOUNTID",
                                "RESOURCEID",
                            ]
                        ],
                        style_table={"overflowX": "auto"},
                        style_as_list_view=True,
                        style_cell={"textAlign": "left", "padding": "5px"},
                    )

                    # Create the graph for req_id
                    fig_tipo = go.Figure(
                        data=[
                            go.Bar(
                                name="Failed",
                                x=[failed_tipo],
                                y=[""],
                                orientation="h",
                                marker=dict(color="#e77676"),
                            ),
                            go.Bar(
                                name="Success",
                                x=[success_tipo],
                                y=[""],
                                orientation="h",
                                marker=dict(color="#45cc6e"),
                            ),
                        ]
                    )

                    fig_tipo.update_layout(
                        barmode="stack",
                        margin=dict(l=10, r=10, t=10, b=10),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        showlegend=False,
                        width=350,
                        height=30,
                        xaxis=dict(
                            showticklabels=False, showgrid=False, zeroline=False
                        ),
                        yaxis=dict(
                            showticklabels=False, showgrid=False, zeroline=False
                        ),
                        annotations=[
                            dict(
                                x=success_tipo + failed_tipo,
                                y=0,
                                xref="x",
                                yref="y",
                                text=str(success_tipo),
                                showarrow=False,
                                font=dict(color="#45cc6e", size=14),
                                xanchor="left",
                                yanchor="middle",
                            ),
                            dict(
                                x=0,
                                y=0,
                                xref="x",
                                yref="y",
                                text=str(failed_tipo),
                                showarrow=False,
                                font=dict(color="#e77676", size=14),
                                xanchor="right",
                                yanchor="middle",
                            ),
                        ],
                    )

                    fig_tipo.add_annotation(
                        x=50,
                        y=0,
                        text="",
                        showarrow=False,
                        align="center",
                        xanchor="center",
                        yanchor="middle",
                        textangle=0,
                    )

                    fig_tipo.add_annotation(
                        x=failed_tipo,
                        y=0.3,
                        text="|",
                        showarrow=False,
                        align="center",
                        xanchor="center",
                        yanchor="middle",
                        textangle=0,
                        font=dict(size=20),
                    )

                    graph_tipo = dcc.Graph(
                        figure=fig_tipo,
                        config={"staticPlot": True},
                        className="info-bar-child",
                    )

                    graph_div_tipo = html.Div(graph_tipo, className="graph-section-req")
                    internal_accordion_item_3 = dbc.AccordionItem(
                        title=tipo,
                        children=[
                            html.Div([data_table], className="inner-accordion-content")
                        ],
                    )
                    internal_section_container_3 = html.Div(
                        [
                            graph_div_tipo,
                            dbc.Accordion(
                                [internal_accordion_item_3],
                                start_collapsed=True,
                                flush=True,
                            ),
                        ],
                        className="accordion-inner--child",
                    )
                    direct_internal_items_tipo.append(internal_section_container_3)

                internal_accordion_item_2 = dbc.AccordionItem(
                    title=idgrupocontrol,
                    children=direct_internal_items_tipo,
                )
                internal_section_container_2 = html.Div(
                    [
                        graph_div_idgrupocontrol,
                        dbc.Accordion(
                            [internal_accordion_item_2],
                            start_collapsed=True,
                            flush=True,
                        ),
                    ],
                    className="accordion-inner--child",
                )
                direct_internal_items_idgrupocontrol.append(
                    internal_section_container_2
                )

            internal_accordion_item = dbc.AccordionItem(
                title=categoria,
                children=direct_internal_items_idgrupocontrol,
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
            title=f"{marco}", children=direct_internal_items
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


# This function extracts and compares up to two numeric values, ensuring correct sorting for version-like strings.
def extract_numeric_values(value):
    numbers = re.findall(r"\d+", str(value))
    if len(numbers) >= 2:
        return int(numbers[0]), int(numbers[1])
    elif len(numbers) == 1:
        return int(numbers[0]), 0
    return 0, 0


def get_section_containers_kisa_ismsp(data, section_1, section_2):
    data["STATUS"] = data["STATUS"].apply(map_status_to_icon)
    data[section_1] = data[section_1].astype(str)
    data[section_2] = data[section_2].astype(str)
    data.sort_values(
        by=section_1,
        key=lambda x: x.map(extract_numeric_values),
        ascending=True,
        inplace=True,
    )

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
                    marker=dict(color="#e77676"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_name],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#45cc6e"),
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
                    font=dict(color="#45cc6e", size=14),
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
                    font=dict(color="#e77676", size=14),
                    xanchor="right",
                    yanchor="middle",
                ),
            ],
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

            fig_section = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_section],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#e77676"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_section],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#45cc6e"),
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
                        font=dict(color="#45cc6e", size=14),
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
                        font=dict(color="#e77676", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
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
