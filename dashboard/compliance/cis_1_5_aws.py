import warnings

import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from dash import dash_table, dcc, html

warnings.filterwarnings("ignore")
import dash_table
from dashboard.common_methods import map_status_to_icon, version_tuple
from dashboard.config import pass_emoji, fail_emoji

def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()
    aux["STATUS"] = aux["STATUS"].apply(map_status_to_icon)
    aux.sort_values(
        by="REQUIREMENTS_ID", key=lambda x: x.map(version_tuple), inplace=True
    )
    aux["REQUIREMENTS_ID"] = aux["REQUIREMENTS_ID"].astype(str)
    aux.drop_duplicates(keep="first", inplace=True)

    findings_counts_section = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_SECTION", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )
    findings_counts_id = (
        aux.groupby(["REQUIREMENTS_ID", "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for section in aux["REQUIREMENTS_ATTRIBUTES_SECTION"].unique():
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
        for req_id in aux[aux["REQUIREMENTS_ATTRIBUTES_SECTION"] == section][
            "REQUIREMENTS_ID"
        ].unique():
            specific_data = aux[
                (aux["REQUIREMENTS_ATTRIBUTES_SECTION"] == section)
                & (aux["REQUIREMENTS_ID"] == req_id)
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
