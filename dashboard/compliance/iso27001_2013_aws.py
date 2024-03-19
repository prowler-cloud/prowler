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
            "REQUIREMENTS_ATTRIBUTES_CATEGORY",
            "REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID",
            "REQUIREMENTS_ATTRIBUTES_OBJETIVE_NAME",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    aux["STATUS"] = aux["STATUS"].apply(map_status_to_icon)
    aux.drop_duplicates(keep="first", inplace=True)
    aux.sort_values(
        by="REQUIREMENTS_ATTRIBUTES_CATEGORY",
        key=lambda x: x.map(version_tuple),
        inplace=True,
    )
    aux.sort_values(
        by="REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID",
        key=lambda x: x.map(version_tuple),
        inplace=True,
    )
    findings_counts_objetive_id = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )
    findings_counts_category = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_CATEGORY", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )

    section_containers = []

    for category in aux["REQUIREMENTS_ATTRIBUTES_CATEGORY"].unique():
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
        for objetive_id in aux[aux["REQUIREMENTS_ATTRIBUTES_CATEGORY"] == category][
            "REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID"
        ].unique():
            specific_data = aux[
                (aux["REQUIREMENTS_ATTRIBUTES_CATEGORY"] == category)
                & (aux["REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID"] == objetive_id)
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
