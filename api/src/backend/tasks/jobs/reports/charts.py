import gc
import io
import math
from typing import Callable

import matplotlib

# Use non-interactive Agg backend for memory efficiency in server environments
# This MUST be set before importing pyplot
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .config import (  # noqa: E402
    CHART_COLOR_BLUE,
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    CHART_DPI_DEFAULT,
)

# Use centralized DPI setting from config
DEFAULT_CHART_DPI = CHART_DPI_DEFAULT


def get_chart_color_for_percentage(percentage: float) -> str:
    """Get chart color string based on percentage.

    Args:
        percentage: Value between 0 and 100

    Returns:
        Hex color string for matplotlib
    """
    if percentage >= 80:
        return CHART_COLOR_GREEN_1
    if percentage >= 60:
        return CHART_COLOR_GREEN_2
    if percentage >= 40:
        return CHART_COLOR_YELLOW
    if percentage >= 20:
        return CHART_COLOR_ORANGE
    return CHART_COLOR_RED


def create_vertical_bar_chart(
    labels: list[str],
    values: list[float],
    ylabel: str = "Compliance Score (%)",
    xlabel: str = "Section",
    title: str | None = None,
    color_func: Callable[[float], str] | None = None,
    colors: list[str] | None = None,
    figsize: tuple[int, int] = (10, 6),
    dpi: int = DEFAULT_CHART_DPI,
    y_limit: tuple[float, float] = (0, 100),
    show_labels: bool = True,
    rotation: int = 45,
) -> io.BytesIO:
    """Create a vertical bar chart.

    Args:
        labels: X-axis labels
        values: Bar heights (numeric values)
        ylabel: Y-axis label
        xlabel: X-axis label
        title: Optional chart title
        color_func: Function to determine bar color based on value
        colors: Explicit list of colors (overrides color_func)
        figsize: Figure size (width, height) in inches
        dpi: Resolution for output image
        y_limit: Y-axis limits (min, max)
        show_labels: Whether to show value labels on bars
        rotation: X-axis label rotation angle

    Returns:
        BytesIO buffer containing the PNG image
    """
    if color_func is None:
        color_func = get_chart_color_for_percentage

    fig, ax = plt.subplots(figsize=figsize)

    # Determine colors
    if colors is None:
        colors_list = [color_func(v) for v in values]
    else:
        colors_list = colors

    bars = ax.bar(labels, values, color=colors_list)

    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylim(*y_limit)

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold")

    # Add value labels on bars
    if show_labels:
        for bar_item, value in zip(bars, values):
            height = bar_item.get_height()
            ax.text(
                bar_item.get_x() + bar_item.get_width() / 2.0,
                height + 1,
                f"{value:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    plt.xticks(rotation=rotation, ha="right")
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=dpi, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()  # Force garbage collection after heavy matplotlib operation

    return buffer


def create_horizontal_bar_chart(
    labels: list[str],
    values: list[float],
    xlabel: str = "Compliance (%)",
    title: str | None = None,
    color_func: Callable[[float], str] | None = None,
    colors: list[str] | None = None,
    figsize: tuple[int, int] | None = None,
    dpi: int = DEFAULT_CHART_DPI,
    x_limit: tuple[float, float] = (0, 100),
    show_labels: bool = True,
    label_fontsize: int = 16,
) -> io.BytesIO:
    """Create a horizontal bar chart.

    Args:
        labels: Y-axis labels (bar names)
        values: Bar widths (numeric values)
        xlabel: X-axis label
        title: Optional chart title
        color_func: Function to determine bar color based on value
        colors: Explicit list of colors (overrides color_func)
        figsize: Figure size (auto-calculated if None based on label count)
        dpi: Resolution for output image
        x_limit: X-axis limits (min, max)
        show_labels: Whether to show value labels on bars
        label_fontsize: Font size for y-axis labels

    Returns:
        BytesIO buffer containing the PNG image
    """
    if color_func is None:
        color_func = get_chart_color_for_percentage

    # Auto-calculate figure size based on number of items
    if figsize is None:
        figsize = (10, max(6, int(len(labels) * 0.4)))

    fig, ax = plt.subplots(figsize=figsize)

    # Determine colors
    if colors is None:
        colors_list = [color_func(v) for v in values]
    else:
        colors_list = colors

    y_pos = range(len(labels))
    bars = ax.barh(y_pos, values, color=colors_list)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=label_fontsize)
    ax.set_xlabel(xlabel, fontsize=14)
    ax.set_xlim(*x_limit)

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold")

    # Add value labels
    if show_labels:
        for bar_item, value in zip(bars, values):
            width = bar_item.get_width()
            ax.text(
                width + 1,
                bar_item.get_y() + bar_item.get_height() / 2.0,
                f"{value:.1f}%",
                ha="left",
                va="center",
                fontweight="bold",
                fontsize=10,
            )

    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=dpi, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()  # Force garbage collection after heavy matplotlib operation

    return buffer


def create_radar_chart(
    labels: list[str],
    values: list[float],
    color: str = CHART_COLOR_BLUE,
    fill_alpha: float = 0.25,
    figsize: tuple[int, int] = (8, 8),
    dpi: int = DEFAULT_CHART_DPI,
    y_limit: tuple[float, float] = (0, 100),
    y_ticks: list[int] | None = None,
    label_fontsize: int = 14,
    title: str | None = None,
) -> io.BytesIO:
    """Create a radar/spider chart.

    Args:
        labels: Category names around the chart
        values: Values for each category (should have same length as labels)
        color: Line and fill color
        fill_alpha: Transparency of the fill (0-1)
        figsize: Figure size (width, height) in inches
        dpi: Resolution for output image
        y_limit: Radial axis limits (min, max)
        y_ticks: Custom tick values for radial axis
        label_fontsize: Font size for category labels
        title: Optional chart title

    Returns:
        BytesIO buffer containing the PNG image
    """
    num_vars = len(labels)
    angles = [n / float(num_vars) * 2 * math.pi for n in range(num_vars)]

    # Close the polygon
    values_closed = list(values) + [values[0]]
    angles_closed = angles + [angles[0]]

    fig, ax = plt.subplots(figsize=figsize, subplot_kw={"projection": "polar"})

    ax.plot(angles_closed, values_closed, "o-", linewidth=2, color=color)
    ax.fill(angles_closed, values_closed, alpha=fill_alpha, color=color)

    ax.set_xticks(angles)
    ax.set_xticklabels(labels, fontsize=label_fontsize)
    ax.set_ylim(*y_limit)

    if y_ticks is None:
        y_ticks = [20, 40, 60, 80, 100]
    ax.set_yticks(y_ticks)
    ax.set_yticklabels([f"{t}%" for t in y_ticks], fontsize=12)

    ax.grid(True, alpha=0.3)

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold", y=1.08)

    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=dpi, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()  # Force garbage collection after heavy matplotlib operation

    return buffer


def create_pie_chart(
    labels: list[str],
    values: list[float],
    colors: list[str] | None = None,
    figsize: tuple[int, int] = (6, 6),
    dpi: int = DEFAULT_CHART_DPI,
    autopct: str = "%1.1f%%",
    startangle: int = 90,
    title: str | None = None,
) -> io.BytesIO:
    """Create a pie chart.

    Args:
        labels: Slice labels
        values: Slice values
        colors: Optional list of colors for slices
        figsize: Figure size (width, height) in inches
        dpi: Resolution for output image
        autopct: Format string for percentage labels
        startangle: Starting angle for first slice
        title: Optional chart title

    Returns:
        BytesIO buffer containing the PNG image
    """
    fig, ax = plt.subplots(figsize=figsize)

    _, _, autotexts = ax.pie(
        values,
        labels=labels,
        colors=colors,
        autopct=autopct,
        startangle=startangle,
    )

    # Style the text
    for autotext in autotexts:
        autotext.set_fontweight("bold")

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold")

    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=dpi, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()  # Force garbage collection after heavy matplotlib operation

    return buffer


def create_stacked_bar_chart(
    labels: list[str],
    data_series: dict[str, list[float]],
    colors: dict[str, str] | None = None,
    xlabel: str = "",
    ylabel: str = "Count",
    title: str | None = None,
    figsize: tuple[int, int] = (10, 6),
    dpi: int = DEFAULT_CHART_DPI,
    rotation: int = 45,
    show_legend: bool = True,
) -> io.BytesIO:
    """Create a stacked bar chart.

    Args:
        labels: X-axis labels
        data_series: Dictionary mapping series name to list of values
        colors: Dictionary mapping series name to color
        xlabel: X-axis label
        ylabel: Y-axis label
        title: Optional chart title
        figsize: Figure size (width, height) in inches
        dpi: Resolution for output image
        rotation: X-axis label rotation angle
        show_legend: Whether to show the legend

    Returns:
        BytesIO buffer containing the PNG image
    """
    fig, ax = plt.subplots(figsize=figsize)

    # Default colors if not provided
    default_colors = {
        "Pass": CHART_COLOR_GREEN_1,
        "Fail": CHART_COLOR_RED,
        "Manual": CHART_COLOR_YELLOW,
    }
    if colors is None:
        colors = default_colors

    bottom = [0] * len(labels)
    for series_name, values in data_series.items():
        color = colors.get(series_name, CHART_COLOR_BLUE)
        ax.bar(labels, values, bottom=bottom, label=series_name, color=color)
        bottom = [b + v for b, v in zip(bottom, values)]

    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold")

    plt.xticks(rotation=rotation, ha="right")

    if show_legend:
        ax.legend()

    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=dpi, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()  # Force garbage collection after heavy matplotlib operation

    return buffer
