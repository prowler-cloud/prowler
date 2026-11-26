import os
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from api.models import StatusChoices
from celery.utils.log import get_task_logger

from .base import (
    ComplianceData,
    _log_phase,
    get_requirement_metadata,
    load_compliance_data,
)
from .config import ENS_NIVEL_ORDER, ENS_TIPO_ORDER, FrameworkConfig
from .html_renderer import (
    format_date_es,
    logo_svg,
    render_html,
    render_pdf,
    ring_svg,
    stacked_bars_svg,
    status_bar_svg,
)

logger = get_task_logger(__name__)

DIMENSIONS = [
    ("trazabilidad", "T", "Trazabilidad", "#4285F4"),
    ("autenticidad", "A", "Autenticidad", "#4DB04F"),
    ("integridad", "I", "Integridad", "#9C27B0"),
    ("confidencialidad", "C", "Confidencialidad", "#F44336"),
    ("disponibilidad", "D", "Disponibilidad", "#FF9800"),
]
NIVEL_COLORS = {
    "alto": "#C8243F",
    "medio": "#C9A000",
    "bajo": "#1F9D6B",
    "opcional": "#7A8290",
}
STATUS_LABELS = {
    StatusChoices.PASS: "Cumple",
    StatusChoices.FAIL: "No cumple",
    StatusChoices.MANUAL: "Manual",
}
TIPO_LABELS = {"recomendacion": "Recomendación"}


def _dimension_keys(raw: Any) -> list[str]:
    if not raw:
        return []
    items = raw.split(",") if isinstance(raw, str) else raw
    return [str(item).strip().lower() for item in items if str(item).strip()]


def _label(value: str) -> str:
    return TIPO_LABELS.get(value.lower(), value.capitalize()) if value else ""


def _share(passed: int, failed: int) -> float | None:
    return passed / (passed + failed) if passed + failed else None


def build_ens_context(
    data: ComplianceData,
    include_manual: bool = True,
    generated_at: datetime | None = None,
) -> dict:
    """Aggregate ENS compliance data into the template context."""
    generated_at = generated_at or datetime.now(UTC)
    rows = []
    for req in data.requirements:
        meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
        if meta is None:
            continue
        dimension_keys = _dimension_keys(getattr(meta, "Dimensiones", []))
        rows.append(
            {
                "id": req.id,
                "title": req.description,
                "description": getattr(meta, "DescripcionControl", "")
                or req.description,
                "status": req.status,
                "status_label": STATUS_LABELS.get(req.status, req.status),
                "marco": getattr(meta, "Marco", "") or "Otros",
                "categoria": getattr(meta, "Categoria", "") or "Sin categoría",
                "nivel": (getattr(meta, "Nivel", "") or "").lower(),
                "tipo": (getattr(meta, "Tipo", "") or "").lower(),
                "tipo_label": _label(getattr(meta, "Tipo", "") or ""),
                "modo": getattr(meta, "ModoEjecucion", "") or "",
                "grupo": getattr(meta, "IdGrupoControl", "") or "",
                "dimensions": [
                    {"key": key, "abbr": abbr, "name": name, "color": color}
                    for key, abbr, name, color in DIMENSIONS
                    if key in dimension_keys
                ],
                "passed_findings": req.passed_findings,
                "failed_findings": req.failed_findings,
            }
        )

    evaluable = [r for r in rows if r["status"] != StatusChoices.MANUAL]
    passed = sum(1 for r in evaluable if r["status"] == StatusChoices.PASS)
    failed = len(evaluable) - passed
    manual = len(rows) - len(evaluable)
    share = _share(passed, failed)

    def tally(key_of) -> dict[str, list[int]]:
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in evaluable:
            for key in key_of(r):
                counts[key][0 if r["status"] == StatusChoices.PASS else 1] += 1
        return counts

    by_categoria = tally(
        lambda r: [(r["marco"].capitalize(), r["categoria"].capitalize())]
    )
    by_marco = tally(lambda r: [r["marco"].capitalize()])
    by_nivel = tally(lambda r: [r["nivel"]])
    by_tipo = tally(lambda r: [r["tipo"]])
    by_dimension = tally(lambda r: [d["key"] for d in r["dimensions"]])

    categoria_rows = sorted(by_categoria.items(), key=lambda kv: (-kv[1][1], kv[0]))
    nivel_rows = [(_label(k), *by_nivel[k]) for k in ENS_NIVEL_ORDER if k in by_nivel]
    tipo_rows = [(_label(k), *by_tipo[k]) for k in ENS_TIPO_ORDER if k in by_tipo]
    dimension_rows = [
        (name, *by_dimension[key])
        for key, _, name, _ in DIMENSIONS
        if key in by_dimension
    ]

    critical_failed = sorted(
        (
            r
            for r in evaluable
            if r["status"] == StatusChoices.FAIL and r["nivel"] == "alto"
        ),
        key=lambda r: (-r["failed_findings"], r["id"]),
    )
    detail_statuses = {StatusChoices.FAIL} | (
        {StatusChoices.MANUAL} if include_manual else set()
    )
    detail = [r for r in rows if r["status"] in detail_statuses]

    index: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in sorted(evaluable, key=lambda r: r["id"]):
        index[r["marco"].capitalize()][r["categoria"].capitalize()].append(r)

    top_categoria = next(((k, v[1]) for k, v in categoria_rows if v[1]), None)

    provider = data.provider_obj
    provider_type = provider.provider.upper() if provider else ""
    account = (provider.alias or provider.uid) if provider else ""
    info_rows = [
        ("Framework", data.framework),
        ("ID", data.compliance_id),
        ("Nombre", data.name),
        ("Versión", data.version),
    ]
    if provider:
        info_rows += [
            ("Proveedor", provider_type),
            ("Account ID", provider.uid or "N/A"),
            ("Alias", provider.alias or "N/A"),
        ]
    info_rows.append(("Scan ID", data.scan_id))
    if data.description:
        info_rows.append(("Descripción", data.description))

    return {
        "data": data,
        "provider_type": provider_type,
        "provider_uid": provider.uid if provider else "",
        "account": account,
        "issued": format_date_es(generated_at),
        "info_rows": info_rows,
        "counts": {
            "pass": passed,
            "fail": failed,
            "manual": manual,
            "total": len(rows),
        },
        "share": share,
        "critical_failed": critical_failed,
        "top_categoria": top_categoria,
        "marco_rows": [(k, *v) for k, v in by_marco.items()],
        "nivel_rows": nivel_rows,
        "tipo_rows": tipo_rows,
        "detail": detail,
        "include_manual": include_manual,
        "index": {marco: dict(cats) for marco, cats in index.items()},
        "nivel_colors": NIVEL_COLORS,
        "dimensions": DIMENSIONS,
        "svg": {
            "logo_cover": logo_svg(34, "#FFFFFF"),
            "logo_header": logo_svg(14, "#14181F"),
            "ring": ring_svg(share, "automatizado"),
            "status_bar": status_bar_svg(passed, failed, manual),
            "categorias": stacked_bars_svg(
                [(f"{c}", p, f) for (_, c), (p, f) in categoria_rows]
            ),
            "dimensiones": stacked_bars_svg(dimension_rows, width=300, label_width=104),
            "niveles": stacked_bars_svg(nivel_rows, width=300, label_width=104),
        },
    }


class ENSReportGenerator:
    """ENS RD 311/2022 compliance report rendered from an HTML template."""

    template_name = "ens.html.j2"

    def __init__(self, config: FrameworkConfig):
        self.config = config

    def generate(
        self,
        tenant_id: str,
        scan_id: str,
        compliance_id: str,
        output_path: str,
        provider_id: str,
        provider_obj=None,
        requirement_statistics: dict[str, dict[str, int]] | None = None,
        findings_cache: dict | None = None,
        prowler_provider: Any | None = None,
        include_manual: bool = True,
        **kwargs,
    ) -> None:
        framework = self.config.display_name
        logger.info(
            "report_generation_start framework=%s scan_id=%s compliance_id=%s",
            framework,
            scan_id,
            compliance_id,
        )
        try:
            _validate_output_path(output_path)
            with _log_phase(
                "load_compliance_data", scan_id=scan_id, framework=framework
            ):
                data = load_compliance_data(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    compliance_id=compliance_id,
                    provider_id=provider_id,
                    provider_obj=provider_obj,
                    requirement_statistics=requirement_statistics,
                    findings_cache=findings_cache,
                    prowler_provider=prowler_provider,
                )
            with _log_phase("render_html", scan_id=scan_id, framework=framework):
                html = render_html(
                    self.template_name, build_ens_context(data, include_manual)
                )
            with _log_phase("doc_build", scan_id=scan_id, framework=framework):
                render_pdf(
                    html,
                    output_path,
                    {
                        "title": f"{framework} Report - {data.framework}",
                        "subject": f"Compliance Report for {data.framework}",
                        "keywords": f"compliance,{data.framework},security,framework,prowler",
                    },
                )
            logger.info(
                "report_generation_end framework=%s scan_id=%s output_path=%s",
                framework,
                scan_id,
                output_path,
            )
        except Exception:
            logger.exception(
                "report_generation_failed framework=%s scan_id=%s compliance_id=%s",
                framework,
                scan_id,
                compliance_id,
            )
            raise


def _validate_output_path(output_path: str) -> None:
    if not isinstance(output_path, str):
        raise TypeError(
            "output_path must be a filesystem path string; "
            f"got {type(output_path).__name__}"
        )
    parent_dir = os.path.dirname(output_path)
    if parent_dir and not os.path.isdir(parent_dir):
        raise FileNotFoundError(f"Output directory does not exist: {parent_dir}")
