from typing import List

from dash import html


def create_provider_card(
    provider: str, provider_logo: str, account_type: str, filtered_data
) -> List[html.Div]:
    """
    Card to display the provider's name and icon.
    Args:
        provider (str): Name of the provider.
        provider_icon (str): Icon of the provider.
    Returns:
        html.Div: Card to display the provider's name and icon.
    """
    accounts = len(
        filtered_data[filtered_data["PROVIDER"] == provider]["ACCOUNT_UID"].unique()
    )
    checks_executed = len(
        filtered_data[filtered_data["PROVIDER"] == provider]["CHECK_ID"].unique()
    )
    fails = len(
        filtered_data[
            (filtered_data["PROVIDER"] == provider)
            & (filtered_data["STATUS"] == "FAIL")
        ]
    )
    passes = len(
        filtered_data[
            (filtered_data["PROVIDER"] == provider)
            & (filtered_data["STATUS"] == "PASS")
        ]
    )
    # Take the values in the MUTED colum that are true for the provider
    if "MUTED" in filtered_data.columns:
        muted = len(
            filtered_data[
                (filtered_data["PROVIDER"] == provider)
                & (filtered_data["MUTED"] == "True")
            ]
        )
    else:
        muted = 0

    return [
        html.Div(
            [
                html.Div(
                    [
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.Div([provider_logo], className="w-8"),
                                    ],
                                    className="p-2 shadow-box-up rounded-full",
                                ),
                                html.H5(
                                    f"{provider.upper()} {account_type}",
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
                                            account_type,
                                            className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                        ),
                                        html.Div(
                                            accounts,
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
                                            checks_executed,
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
                                                    fails,
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
                                                    passes,
                                                    className="m-[2px] px-4 py-1 rounded-lg bg-gradient-passed",
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
                                            "MUTED",
                                            className="text-prowler-stone-900 inline-block text-3xs font-bold uppercase transition-all rounded-lg text-prowler-stone-900 shadow-box-up px-4 py-1 text-center col-span-6 flex justify-center items-center",
                                        ),
                                        html.Div(
                                            [
                                                html.Div(
                                                    muted,
                                                    className="m-[2px] px-4 py-1 rounded-lg bg-gradient-muted",
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
