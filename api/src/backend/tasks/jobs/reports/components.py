from dataclasses import dataclass
from typing import Any, Callable

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import LongTable, Paragraph, Spacer, Table, TableStyle

from .config import (
    ALTERNATE_ROWS_MAX_SIZE,
    COLOR_BLUE,
    COLOR_BORDER_GRAY,
    COLOR_DARK_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HIGH_RISK,
    COLOR_LIGHT_GRAY,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_SAFE,
    COLOR_WHITE,
    LONG_TABLE_THRESHOLD,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    PADDING_XLARGE,
)


def get_color_for_risk_level(risk_level: int) -> colors.Color:
    """
    Get color based on risk level.

    Args:
        risk_level (int): Numeric risk level (0-5).

    Returns:
        colors.Color: Appropriate color for the risk level.
    """
    if risk_level >= 4:
        return COLOR_HIGH_RISK
    if risk_level >= 3:
        return COLOR_MEDIUM_RISK
    if risk_level >= 2:
        return COLOR_LOW_RISK
    return COLOR_SAFE


def get_color_for_weight(weight: int) -> colors.Color:
    """
    Get color based on weight value.

    Args:
        weight (int): Numeric weight value.

    Returns:
        colors.Color: Appropriate color for the weight.
    """
    if weight > 100:
        return COLOR_HIGH_RISK
    if weight > 50:
        return COLOR_LOW_RISK
    return COLOR_SAFE


def get_color_for_compliance(percentage: float) -> colors.Color:
    """
    Get color based on compliance percentage.

    Args:
        percentage (float): Compliance percentage (0-100).

    Returns:
        colors.Color: Appropriate color for the compliance level.
    """
    if percentage >= 80:
        return COLOR_SAFE
    if percentage >= 60:
        return COLOR_LOW_RISK
    return COLOR_HIGH_RISK


def get_status_color(status: str) -> colors.Color:
    """
    Get color for a status value.

    Args:
        status (str): Status string (PASS, FAIL, MANUAL, etc.).

    Returns:
        colors.Color: Appropriate color for the status.
    """
    status_upper = status.upper()
    if status_upper == "PASS":
        return COLOR_SAFE
    if status_upper == "FAIL":
        return COLOR_HIGH_RISK
    return COLOR_DARK_GRAY


def create_badge(
    text: str,
    bg_color: colors.Color,
    text_color: colors.Color = COLOR_WHITE,
    width: float = 1.4 * inch,
    font: str = "FiraCode",
    font_size: int = 11,
) -> Table:
    """
    Create a generic colored badge component.

    Args:
        text (str): Text to display in the badge.
        bg_color (colors.Color): Background color.
        text_color (colors.Color): Text color (default white).
        width (float): Badge width in inches.
        font (str): Font name to use.
        font_size (int): Font size.

    Returns:
        Table: A Table object styled as a badge.
    """
    data = [[text]]
    table = Table(data, colWidths=[width])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), bg_color),
                ("TEXTCOLOR", (0, 0), (0, 0), text_color),
                ("FONTNAME", (0, 0), (0, 0), font),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
            ]
        )
    )

    return table


def create_status_badge(status: str) -> Table:
    """
    Create a PASS/FAIL/MANUAL status badge.

    Args:
        status (str): Status value (e.g., "PASS", "FAIL", "MANUAL").

    Returns:
        Table: A styled Table badge for the status.
    """
    status_upper = status.upper()
    status_color = get_status_color(status_upper)

    data = [["State:", status_upper]]
    table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("BACKGROUND", (1, 0), (1, 0), status_color),
                ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
            ]
        )
    )

    return table


def create_multi_badge_row(
    badges: list[tuple[str, colors.Color]],
    badge_width: float = 0.4 * inch,
    font: str = "FiraCode",
) -> Table:
    """
    Create a row of multiple small badges.

    Args:
        badges (list[tuple[str, colors.Color]]): List of (text, color) tuples for each badge.
        badge_width (float): Width of each badge.
        font (str): Font name to use.

    Returns:
        Table: A Table with multiple colored badges in a row.
    """
    if not badges:
        data = [["N/A"]]
        table = Table(data, colWidths=[1 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                ]
            )
        )
        return table

    data = [[text for text, _ in badges]]
    col_widths = [badge_width] * len(badges)
    table = Table(data, colWidths=col_widths)

    styles = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), font),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("LEFTPADDING", (0, 0), (-1, -1), PADDING_SMALL),
        ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_SMALL),
        ("TOPPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
    ]

    for idx, (_, badge_color) in enumerate(badges):
        styles.append(("BACKGROUND", (idx, 0), (idx, 0), badge_color))

    table.setStyle(TableStyle(styles))
    return table


def create_risk_component(
    risk_level: int,
    weight: int,
    score: int = 0,
) -> Table:
    """
    Create a visual risk component showing risk level, weight, and score.

    Args:
        risk_level (int): The risk level (0-5).
        weight (int): The weight value.
        score (int): The calculated score (default 0).

    Returns:
        Table: A styled Table showing risk metrics.
    """
    risk_color = get_color_for_risk_level(risk_level)
    weight_color = get_color_for_weight(weight)

    data = [
        [
            "Risk Level:",
            str(risk_level),
            "Weight:",
            str(weight),
            "Score:",
            str(score),
        ]
    ]

    table = Table(
        data,
        colWidths=[
            0.8 * inch,
            0.4 * inch,
            0.6 * inch,
            0.4 * inch,
            0.5 * inch,
            0.4 * inch,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (1, 0), (1, 0), risk_color),
                ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("BACKGROUND", (2, 0), (2, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (3, 0), (3, 0), weight_color),
                ("TEXTCOLOR", (3, 0), (3, 0), COLOR_WHITE),
                ("FONTNAME", (3, 0), (3, 0), "FiraCode"),
                ("BACKGROUND", (4, 0), (4, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (5, 0), (5, 0), COLOR_DARK_GRAY),
                ("TEXTCOLOR", (5, 0), (5, 0), COLOR_WHITE),
                ("FONTNAME", (5, 0), (5, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
            ]
        )
    )

    return table


def create_info_table(
    rows: list[tuple[str, Any]],
    label_width: float = 2 * inch,
    value_width: float = 4 * inch,
    label_color: colors.Color = COLOR_BLUE,
    value_bg_color: colors.Color | None = None,
    normal_style: ParagraphStyle | None = None,
) -> Table:
    """
    Create a key-value information table.

    Args:
        rows (list[tuple[str, Any]]): List of (label, value) tuples.
        label_width (float): Width of the label column.
        value_width (float): Width of the value column.
        label_color (colors.Color): Background color for labels.
        value_bg_color (colors.Color | None): Background color for values (optional).
        normal_style (ParagraphStyle | None): ParagraphStyle for wrapping long values.

    Returns:
        Table: A styled Table with key-value pairs.
    """
    from .config import COLOR_BG_BLUE

    if value_bg_color is None:
        value_bg_color = COLOR_BG_BLUE

    # Handle empty rows case - Table requires at least one row
    if not rows:
        table = Table([["", ""]], colWidths=[label_width, value_width])
        table.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 0)]))
        return table

    # Process rows - wrap long values in Paragraph if style provided
    table_data = []
    for label, value in rows:
        if normal_style and isinstance(value, str) and len(value) > 50:
            value = Paragraph(value, normal_style)
        table_data.append([label, value])

    table = Table(table_data, colWidths=[label_width, value_width])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), label_color),
                ("TEXTCOLOR", (0, 0), (0, -1), COLOR_WHITE),
                ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                ("BACKGROUND", (1, 0), (1, -1), value_bg_color),
                ("TEXTCOLOR", (1, 0), (1, -1), COLOR_DARK_GRAY),
                ("FONTNAME", (1, 0), (1, -1), "PlusJakartaSans"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER_GRAY),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
            ]
        )
    )

    return table


@dataclass
class ColumnConfig:
    """
    Configuration for a table column.

    Attributes:
        header (str): Column header text.
        width (float): Column width in inches.
        field (str | Callable[[Any], str]): Field name or callable to extract value from data.
        align (str): Text alignment (LEFT, CENTER, RIGHT).
    """

    header: str
    width: float
    field: str | Callable[[Any], str]
    align: str = "CENTER"


def create_data_table(
    data: list[dict[str, Any]],
    columns: list[ColumnConfig],
    header_color: colors.Color = COLOR_BLUE,
    alternate_rows: bool = True,
    normal_style: ParagraphStyle | None = None,
) -> Table | LongTable:
    """
    Create a data table with configurable columns.

    Uses LongTable for large datasets (>50 rows) for better memory efficiency
    and page splitting. LongTable repeats headers on each page and has
    optimized memory handling for large tables.

    Args:
        data (list[dict[str, Any]]): List of data dictionaries.
        columns (list[ColumnConfig]): Column configuration list.
        header_color (colors.Color): Background color for header row.
        alternate_rows (bool): Whether to alternate row backgrounds.
        normal_style (ParagraphStyle | None): ParagraphStyle for cell values.

    Returns:
        Table or LongTable: A styled table with data.
    """
    # Build header row
    header_row = [col.header for col in columns]
    table_data = [header_row]

    # Build data rows
    for item in data:
        row = []
        for col in columns:
            if callable(col.field):
                value = col.field(item)
            else:
                value = item.get(col.field, "")

            if normal_style and isinstance(value, str):
                value = Paragraph(value, normal_style)
            row.append(value)
        table_data.append(row)

    col_widths = [col.width for col in columns]

    # Use LongTable for large datasets - it handles page breaks better
    # and has optimized memory handling for tables with many rows
    use_long_table = len(data) > LONG_TABLE_THRESHOLD
    if use_long_table:
        table = LongTable(table_data, colWidths=col_widths, repeatRows=1)
    else:
        table = Table(table_data, colWidths=col_widths)

    styles = [
        ("BACKGROUND", (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 1, COLOR_GRID_GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ("TOPPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
    ]

    # Apply column alignments
    for idx, col in enumerate(columns):
        styles.append(("ALIGN", (idx, 0), (idx, -1), col.align))

    # Alternate row backgrounds - skip for very large tables as it adds memory overhead
    if (
        alternate_rows
        and len(table_data) > 1
        and len(table_data) <= ALTERNATE_ROWS_MAX_SIZE
    ):
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                styles.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.Color(0.98, 0.98, 0.98))
                )

    table.setStyle(TableStyle(styles))
    return table


def create_findings_table(
    findings: list[Any],
    columns: list[ColumnConfig] | None = None,
    header_color: colors.Color = COLOR_BLUE,
    normal_style: ParagraphStyle | None = None,
) -> Table:
    """
    Create a findings table with default or custom columns.

    Args:
        findings (list[Any]): List of finding objects.
        columns (list[ColumnConfig] | None): Optional column configuration (defaults to standard columns).
        header_color (colors.Color): Background color for header row.
        normal_style (ParagraphStyle | None): ParagraphStyle for cell values.

    Returns:
        Table: A styled Table with findings data.
    """
    if columns is None:
        columns = [
            ColumnConfig("Finding", 2.5 * inch, "title"),
            ColumnConfig("Resource", 3 * inch, "resource_name"),
            ColumnConfig("Severity", 0.9 * inch, "severity"),
            ColumnConfig("Status", 0.9 * inch, "status"),
            ColumnConfig("Region", 0.9 * inch, "region"),
        ]

    # Convert findings to dicts
    data = []
    for finding in findings:
        item = {}
        for col in columns:
            if callable(col.field):
                item[col.header.lower()] = col.field(finding)
            elif hasattr(finding, col.field):
                item[col.field] = getattr(finding, col.field, "")
            elif isinstance(finding, dict):
                item[col.field] = finding.get(col.field, "")
        data.append(item)

    return create_data_table(
        data=data,
        columns=columns,
        header_color=header_color,
        alternate_rows=True,
        normal_style=normal_style,
    )


def create_section_header(
    text: str,
    style: ParagraphStyle,
    add_spacer: bool = True,
    spacer_height: float = 0.2,
) -> list:
    """
    Create a section header with optional spacer.

    Args:
        text (str): Header text.
        style (ParagraphStyle): ParagraphStyle to apply.
        add_spacer (bool): Whether to add a spacer after the header.
        spacer_height (float): Height of the spacer in inches.

    Returns:
        list: List of elements (Paragraph and optional Spacer).
    """
    elements = [Paragraph(text, style)]
    if add_spacer:
        elements.append(Spacer(1, spacer_height * inch))
    return elements


def create_summary_table(
    label: str,
    value: str,
    value_color: colors.Color,
    label_width: float = 2.5 * inch,
    value_width: float = 2 * inch,
) -> Table:
    """
    Create a summary metric table (e.g., for ThreatScore display).

    Args:
        label (str): Label text (e.g., "ThreatScore:").
        value (str): Value text (e.g., "85.5%").
        value_color (colors.Color): Background color for the value cell.
        label_width (float): Width of the label column.
        value_width (float): Width of the value column.

    Returns:
        Table: A styled summary Table.
    """
    data = [[label, value]]
    table = Table(data, colWidths=[label_width, value_width])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.1, 0.3, 0.5)),
                ("TEXTCOLOR", (0, 0), (0, 0), COLOR_WHITE),
                ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                ("FONTSIZE", (0, 0), (0, 0), 12),
                ("BACKGROUND", (1, 0), (1, 0), value_color),
                ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("FONTSIZE", (1, 0), (1, 0), 16),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 1.5, colors.Color(0.5, 0.6, 0.7)),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )

    return table
