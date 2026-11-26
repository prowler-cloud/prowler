"""HTML-to-PDF rendering for compliance reports (Jinja2 templates + WeasyPrint)."""

import math
import os
from datetime import datetime
from functools import lru_cache
from html import escape
from urllib.parse import unquote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

ASSETS_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../assets"))
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

INK = "#14181F"
MUTED = "#7A8290"
GRID = "#E6E8EC"
PASS = "#1F9D6B"
FAIL = "#C8243F"
MANUAL = "#A3A9B3"

_TEXT = {
    "ax": f'font-family="Inter" font-size="10" fill="{MUTED}"',
    "lab": f'font-family="Inter" font-size="11" fill="{INK}"',
    "val": f'font-family="Inter" font-size="11" font-weight="600" fill="{INK}"',
    "inbar": 'font-family="Inter" font-size="12" font-weight="600" fill="#FFFFFF"',
    "big": f'font-family="Inter" font-size="24" font-weight="700" fill="{INK}"',
}

MONTHS_ES = [
    "ene", "feb", "mar", "abr", "may", "jun",
    "jul", "ago", "sep", "oct", "nov", "dic",
]  # fmt: skip


def format_number(value: float) -> str:
    return f"{value:,.0f}".replace(",", ".")


def format_percent(value: float, digits: int = 0) -> str:
    return f"{value:.{digits}f}".replace(".", ",") + " %"


def format_date_es(value: datetime) -> str:
    return f"{value.day} {MONTHS_ES[value.month - 1]} {value.year}"


@lru_cache(maxsize=1)
def _logo_path_data() -> str:
    with open(os.path.join(ASSETS_DIR, "img/prowler_logo.svg")) as f:
        svg = f.read()
    return svg.split(' d="', 1)[1].split('"', 1)[0]


def logo_svg(height: float, color: str) -> str:
    width = height * 1233.67 / 204.4
    return (
        f'<svg viewBox="0 0 1233.67 204.4" width="{width:.1f}" height="{height}">'
        f'<path d="{_logo_path_data()}" fill="{color}" fill-rule="evenodd"/></svg>'
    )


def status_bar_svg(passed: int, failed: int, manual: int, width: int = 680) -> str:
    total = passed + failed + manual
    out = [f'<svg viewBox="0 0 {width} 34" class="chart">']
    if not total:
        out.append(
            f'<rect x="0" y="0" width="{width}" height="34" rx="4" fill="{GRID}"/>'
        )
    x = 0.0
    for value, color, label in (
        (passed, PASS, "Cumple"),
        (failed, FAIL, "No cumple"),
        (manual, MANUAL, "Manual"),
    ):
        w = width * value / total if total else 0
        if w <= 0:
            continue
        out.append(
            f'<rect x="{x:.1f}" y="0" width="{max(w - 2, 1):.1f}" height="34" rx="4" fill="{color}"/>'
        )
        if w > 80:
            out.append(
                f'<text x="{x + 10:.1f}" y="22" {_TEXT["inbar"]}>{label} {value}</text>'
            )
        x += w
    out.append("</svg>")
    return "".join(out)


def stacked_bars_svg(
    rows: list[tuple[str, int, int]], width: int = 680, label_width: int = 230
) -> str:
    """Pass/fail bar per row, labelled with the pass share of evaluable items."""
    row_height = 22
    height = row_height * len(rows) + 4
    plot_width = width - label_width - 60
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart">']
    for i, (label, passed, failed) in enumerate(rows):
        y = 4 + i * row_height
        total = passed + failed
        out.append(f'<text x="0" y="{y + 13}" {_TEXT["lab"]}>{escape(label)}</text>')
        out.append(
            f'<rect x="{label_width}" y="{y + 2}" width="{plot_width}" height="14" rx="3" fill="{GRID}"/>'
        )
        if not total:
            out.append(
                f'<text x="{width}" y="{y + 13}" text-anchor="end" {_TEXT["ax"]}>—</text>'
            )
            continue
        pass_width = plot_width * passed / total
        if passed:
            out.append(
                f'<rect x="{label_width}" y="{y + 2}" width="{pass_width:.1f}" height="14" rx="3" fill="{PASS}"/>'
            )
        if failed:
            gap = 1 if passed else 0
            out.append(
                f'<rect x="{label_width + pass_width + gap:.1f}" y="{y + 2}" '
                f'width="{max(plot_width - pass_width - gap, 1):.1f}" height="14" rx="3" fill="{FAIL}"/>'
            )
        out.append(
            f'<text x="{width}" y="{y + 13}" text-anchor="end" {_TEXT["val"]}>'
            f"{format_percent(passed / total * 100)}</text>"
        )
    out.append("</svg>")
    return "".join(out)


def ring_svg(share: float | None, caption: str, size: int = 150) -> str:
    radius, center = 58, size / 2
    circumference = 2 * math.pi * radius
    label = format_percent(share * 100) if share is not None else "—"
    track = FAIL if share is not None else GRID
    arc = (
        f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="{PASS}" '
        f'stroke-width="14" stroke-dasharray="{circumference * share:.1f} {circumference:.1f}" '
        f'transform="rotate(-90 {center} {center})"/>'
        if share
        else ""
    )
    return (
        f'<svg viewBox="0 0 {size} {size}" class="ring">'
        f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="{track}" stroke-width="14"/>'
        f"{arc}"
        f'<text x="{center}" y="{center + 2}" text-anchor="middle" {_TEXT["big"]}>{label}</text>'
        f'<text x="{center}" y="{center + 20}" text-anchor="middle" {_TEXT["ax"]}>{escape(caption)}</text>'
        "</svg>"
    )


@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["num"] = format_number
    env.filters["pct"] = format_percent
    return env


def render_html(template_name: str, context: dict) -> str:
    return _environment().get_template(template_name).render(**context)


def ensure_bundled_asset(url: str) -> None:
    """Reject any URL outside the bundled assets directory."""
    parsed = urlparse(url)
    path = os.path.realpath(unquote(parsed.path))
    if parsed.scheme != "file" or not path.startswith(ASSETS_DIR + os.sep):
        raise ValueError(f"Report templates may only load bundled assets: {url}")


def render_pdf(html: str, output_path: str, metadata: dict[str, str]) -> int:
    """Write ``html`` as a PDF to ``output_path`` and return its page count."""
    # Imported lazily: WeasyPrint needs Pango at import time, which only the
    # worker image ships.
    from weasyprint import HTML, URLFetcher

    class AssetsOnlyFetcher(URLFetcher):
        def fetch(self, url, headers=None):
            ensure_bundled_asset(url)
            return super().fetch(url, headers)

    document = HTML(
        string=html,
        base_url=ASSETS_DIR + os.sep,
        url_fetcher=AssetsOnlyFetcher(allowed_protocols={"file"}, fail_on_errors=True),
    ).render()
    document.metadata.title = metadata.get("title")
    document.metadata.authors = ["Prowler"]
    document.metadata.description = metadata.get("subject")
    document.metadata.keywords = metadata.get("keywords", "").split(",")
    document.write_pdf(output_path)
    return len(document.pages)
