import warnings

import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from dash import dash_table, dcc, html

warnings.filterwarnings("ignore")
import dash_table
from dashboard.common_methods import map_status_to_icon
from dashboard.config import pass_emoji, fail_emoji

def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ATTRIBUTES_NAME",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    aux["STATUS"] = aux["STATUS"].apply(map_status_to_icon)
    aux.drop_duplicates(keep="first", inplace=True)
    findings_counts_section = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_SECTION", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )
    findings_counts_name = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_NAME", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )

    section_containers = []

    for name in aux["REQUIREMENTS_ATTRIBUTES_NAME"].unique():
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
        for section in aux[aux["REQUIREMENTS_ATTRIBUTES_NAME"] == name][
            "REQUIREMENTS_ATTRIBUTES_SECTION"
        ].unique():
            specific_data = aux[
                (aux["REQUIREMENTS_ATTRIBUTES_NAME"] == name)
                & (aux["REQUIREMENTS_ATTRIBUTES_SECTION"] == section)
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
