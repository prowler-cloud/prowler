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
            "REQUIREMENTS_ATTRIBUTES_SERVICE",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ]
    aux["STATUS"] = aux["STATUS"].apply(map_status_to_icon)
    aux["REQUIREMENTS_ATTRIBUTES_SERVICE"] = aux[
        "REQUIREMENTS_ATTRIBUTES_SERVICE"
    ].astype(str)
    aux.drop_duplicates(keep="first", inplace=True)
    findings_counts_service = (
        aux.groupby(["REQUIREMENTS_ATTRIBUTES_SERVICE", "STATUS"])
        .size()
        .unstack(fill_value=0)
    )

    direct_internal_items = []
    for service in aux["REQUIREMENTS_ATTRIBUTES_SERVICE"].unique():
        specific_data = aux[aux["REQUIREMENTS_ATTRIBUTES_SERVICE"] == service]
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
