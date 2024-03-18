import warnings

import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from dash import dash_table, dcc, html

warnings.filterwarnings("ignore")
import dash_table
from common_methods import map_status_to_icon


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_ATTRIBUTES_TIPO",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    aux["STATUS"] = aux["STATUS"].apply(map_status_to_icon)
    aux.drop_duplicates(keep="first", inplace=True)
    findings_counts_tipo = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_TIPO", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )
    findings_counts_req_id = (
        aux.groupby(["REQUIREMENTS_ID", "STATUS"]).size().unstack(fill_value=0)
    )

    section_containers = []

    for tipo in aux["REQUIREMENTS_ATTRIBUTES_TIPO"].unique():
        success_tipo = (
            findings_counts_tipo.loc[tipo, "✅"]
            if "✅" in findings_counts_tipo.columns
            else 0
        )
        failed_tipo = (
            findings_counts_tipo.loc[tipo, "❌"]
            if "❌" in findings_counts_tipo.columns
            else 0
        )

        fig_tipo = go.Figure(
            data=[
                go.Bar(
                    name="Failed",
                    x=[failed_tipo],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#A3231F"),
                    width=[0.8],
                ),
                go.Bar(
                    name="Success",
                    x=[success_tipo],
                    y=[""],
                    orientation="h",
                    marker=dict(color="#1FB53F"),
                    width=[0.8],
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
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            annotations=[
                dict(
                    x=success_tipo + failed_tipo,
                    y=0,
                    xref="x",
                    yref="y",
                    text=str(success_tipo),
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
                    text=str(failed_tipo),
                    showarrow=False,
                    font=dict(color="#A3231F", size=14),
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
            figure=fig_tipo, config={"staticPlot": True}, className="info-bar"
        )

        graph_div = html.Div(graph_tipo, className="graph-section")

        direct_internal_items = []
        for req_id in aux[aux["REQUIREMENTS_ATTRIBUTES_TIPO"] == tipo][
            "REQUIREMENTS_ID"
        ].unique():
            specific_data = aux[
                (aux["REQUIREMENTS_ATTRIBUTES_TIPO"] == tipo)
                & (aux["REQUIREMENTS_ID"] == req_id)
            ]
            success_req_id = (
                findings_counts_req_id.loc[req_id, "✅"]
                if "✅" in findings_counts_req_id.columns
                else 0
            )
            failed_req_id = (
                findings_counts_req_id.loc[req_id, "❌"]
                if "❌" in findings_counts_req_id.columns
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
            fig_req_id = go.Figure(
                data=[
                    go.Bar(
                        name="Failed",
                        x=[failed_req_id],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#A3231F"),
                    ),
                    go.Bar(
                        name="Success",
                        x=[success_req_id],
                        y=[""],
                        orientation="h",
                        marker=dict(color="#1FB53F"),
                    ),
                ]
            )

            fig_req_id.update_layout(
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
                        x=success_req_id + failed_req_id,
                        y=0,
                        xref="x",
                        yref="y",
                        text=str(success_req_id),
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
                        text=str(failed_req_id),
                        showarrow=False,
                        font=dict(color="#A3231F", size=14),
                        xanchor="right",
                        yanchor="middle",
                    ),
                ],
            )

            fig_req_id.add_annotation(
                x=50,
                y=0,
                text="",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
            )

            fig_req_id.add_annotation(
                x=failed_req_id,
                y=0.3,
                text="|",
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                textangle=0,
                font=dict(size=20),
            )

            graph_req_id = dcc.Graph(
                figure=fig_req_id,
                config={"staticPlot": True},
                className="info-bar-child",
            )

            graph_div_req_id = html.Div(graph_req_id, className="graph-section-req")

            internal_accordion_item = dbc.AccordionItem(
                title=req_id,
                children=[html.Div([data_table], className="inner-accordion-content")],
            )

            internal_req_id_container = html.Div(
                [
                    graph_div_req_id,
                    dbc.Accordion(
                        [internal_accordion_item], start_collapsed=True, flush=True
                    ),
                ],
                className="accordion-inner--child",
            )

            direct_internal_items.append(internal_req_id_container)

        accordion_item = dbc.AccordionItem(
            title=f"{tipo}", children=direct_internal_items
        )
        req_id_container = html.Div(
            [
                graph_div,
                dbc.Accordion([accordion_item], start_collapsed=True, flush=True),
            ],
            className="accordion-inner",
        )

        section_containers.append(req_id_container)

    return html.Div(section_containers, className="compliance-data-layout")
