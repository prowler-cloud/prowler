from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from tasks.jobs.reports import FRAMEWORK_REGISTRY, ComplianceData, RequirementData
from tasks.jobs.reports import ens as ens_module
from tasks.jobs.reports.ens import ENSReportGenerator, build_ens_context
from tasks.jobs.reports.html_renderer import (
    ASSETS_DIR,
    ensure_bundled_asset,
    render_html,
    stacked_bars_svg,
)

PASS, FAIL, MANUAL = "PASS", "FAIL", "MANUAL"


def ens_attribute(**overrides):
    values = {
        "Marco": "operacional",
        "Categoria": "control de acceso",
        "DescripcionControl": "Descripción del control",
        "Tipo": "requisito",
        "Nivel": "alto",
        "Dimensiones": ["confidencialidad", "integridad"],
        "ModoEjecucion": "automático",
        "IdGrupoControl": "op.acc.1",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def compliance_data(requirements, provider_obj=None):
    reqs, attributes = [], {}
    for req_id, status, attribute, failed in requirements:
        reqs.append(
            RequirementData(
                id=req_id,
                description=f"Requisito {req_id}",
                status=status,
                failed_findings=failed,
                passed_findings=1,
            )
        )
        attributes[req_id] = {"attributes": {"req_attributes": [attribute]}}
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="ens_rd2022_aws",
        framework="ENS",
        name="Esquema Nacional de Seguridad RD 311/2022",
        version="RD2022",
        description="Marco de seguridad & cumplimiento",
        requirements=reqs,
        attributes_by_requirement_id=attributes,
        provider_obj=provider_obj,
    )


@pytest.fixture
def mixed_data():
    return compliance_data(
        [
            ("op.acc.1", PASS, ens_attribute(), 0),
            ("op.acc.2", FAIL, ens_attribute(), 3),
            (
                "op.exp.1",
                FAIL,
                ens_attribute(Categoria="explotación", Nivel="medio"),
                9,
            ),
            ("op.exp.2", FAIL, ens_attribute(Categoria="explotación"), 12),
            (
                "mp.s.1",
                MANUAL,
                ens_attribute(Marco="medidas de protección", ModoEjecucion="manual"),
                0,
            ),
        ],
        provider_obj=SimpleNamespace(
            provider="aws", uid="123456789012", alias="acme-prod"
        ),
    )


class TestBuildENSContext:
    def test_automated_share_excludes_manual_requirements(self, mixed_data):
        context = build_ens_context(mixed_data)

        assert context["counts"] == {"pass": 1, "fail": 3, "manual": 1, "total": 5}
        assert context["share"] == pytest.approx(0.25)

    def test_share_is_none_when_nothing_is_evaluable(self):
        data = compliance_data([("mp.s.1", MANUAL, ens_attribute(), 0)])

        assert build_ens_context(data)["share"] is None

    def test_critical_failed_lists_only_failed_nivel_alto_by_failed_findings(
        self, mixed_data
    ):
        critical = build_ens_context(mixed_data)["critical_failed"]

        assert [r["id"] for r in critical] == ["op.exp.2", "op.acc.2"]

    def test_index_excludes_manual_requirements(self, mixed_data):
        index = build_ens_context(mixed_data)["index"]

        ids = [
            r["id"]
            for categorias in index.values()
            for reqs in categorias.values()
            for r in reqs
        ]
        assert "mp.s.1" not in ids
        assert sorted(ids) == ["op.acc.1", "op.acc.2", "op.exp.1", "op.exp.2"]

    def test_detail_includes_manual_requirements_when_requested(self, mixed_data):
        ids = [
            r["id"]
            for r in build_ens_context(mixed_data, include_manual=True)["detail"]
        ]

        assert ids == ["op.acc.2", "op.exp.1", "op.exp.2", "mp.s.1"]

    def test_detail_lists_only_failed_requirements_without_manual(self, mixed_data):
        ids = [
            r["id"]
            for r in build_ens_context(mixed_data, include_manual=False)["detail"]
        ]

        assert ids == ["op.acc.2", "op.exp.1", "op.exp.2"]

    def test_nivel_rows_follow_ens_order_and_count_pass_fail(self, mixed_data):
        assert build_ens_context(mixed_data)["nivel_rows"] == [
            ("Alto", 1, 2),
            ("Medio", 0, 1),
        ]

    def test_top_categoria_is_the_one_with_most_failures(self, mixed_data):
        assert build_ens_context(mixed_data)["top_categoria"] == (
            ("Operacional", "Explotación"),
            2,
        )

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (["Trazabilidad", "disponibilidad"], ["T", "D"]),
            ("trazabilidad, autenticidad", ["T", "A"]),
            ([], []),
            (None, []),
        ],
    )
    def test_dimensions_accept_list_string_or_empty(self, raw, expected):
        data = compliance_data([("op.acc.1", FAIL, ens_attribute(Dimensiones=raw), 1)])

        detail = build_ens_context(data)["detail"][0]

        assert [d["abbr"] for d in detail["dimensions"]] == expected

    def test_requirements_without_metadata_are_skipped(self):
        data = compliance_data([("op.acc.1", PASS, ens_attribute(), 0)])
        data.requirements.append(
            RequirementData(id="orphan", description="", status=FAIL)
        )

        assert build_ens_context(data)["counts"]["total"] == 1

    def test_info_rows_include_provider_identity(self, mixed_data):
        rows = dict(build_ens_context(mixed_data)["info_rows"])

        assert rows["Proveedor"] == "AWS"
        assert rows["Account ID"] == "123456789012"
        assert rows["Alias"] == "acme-prod"
        assert rows["Scan ID"] == "scan-456"

    def test_issue_date_comes_from_generation_time(self, mixed_data):
        context = build_ens_context(
            mixed_data, generated_at=datetime(2026, 11, 26, tzinfo=UTC)
        )

        assert context["issued"] == "26 nov 2026"


class TestENSTemplate:
    def test_renders_every_section(self, mixed_data):
        html = render_html("ens.html.j2", build_ens_context(mixed_data))

        for heading in (
            "Resumen ejecutivo",
            "Cumplimiento por categoría",
            "Requisitos críticos no cumplidos",
            "Índice de requisitos",
            "Detalle de requisitos",
            "Acerca de este informe",
        ):
            assert heading in html

    def test_escapes_framework_text(self, mixed_data):
        html = render_html("ens.html.j2", build_ens_context(mixed_data))

        assert "Marco de seguridad &amp; cumplimiento" in html

    def test_shows_success_message_without_critical_failures(self):
        data = compliance_data([("op.acc.1", PASS, ens_attribute(), 0)])

        html = render_html("ens.html.j2", build_ens_context(data))

        assert "No hay requisitos de nivel alto que hayan fallado." in html

    def test_chart_labels_are_escaped(self):
        svg = stacked_bars_svg([("Audit & Assurance", 1, 1)])

        assert "Audit &amp; Assurance" in svg


class TestAssetGuard:
    def test_allows_bundled_fonts(self):
        ensure_bundled_asset(f"file://{ASSETS_DIR}/fonts/Inter-Regular.ttf")

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/logo.png",
            "file:///etc/passwd",
            f"file://{ASSETS_DIR}/../../config/settings.py",
        ],
    )
    def test_rejects_anything_outside_assets(self, url):
        with pytest.raises(ValueError):
            ensure_bundled_asset(url)


class TestENSReportGenerator:
    @pytest.fixture
    def generator(self):
        return ENSReportGenerator(FRAMEWORK_REGISTRY["ens"])

    def test_rejects_non_string_output_path(self, generator):
        with pytest.raises(TypeError):
            generator.generate("t", "s", "ens_rd2022_aws", Mock(), "p")

    def test_rejects_missing_output_directory(self, generator, tmp_path):
        with pytest.raises(FileNotFoundError):
            generator.generate(
                "t", "s", "ens_rd2022_aws", str(tmp_path / "missing" / "r.pdf"), "p"
            )

    def test_renders_loaded_data_to_output_path(self, generator, mixed_data, tmp_path):
        output = str(tmp_path / "ens.pdf")
        with (
            patch.object(
                ens_module, "load_compliance_data", return_value=mixed_data
            ) as load,
            patch.object(ens_module, "render_pdf", return_value=6) as render,
        ):
            generator.generate(
                "t", "s", "ens_rd2022_aws", output, "p", include_manual=False
            )

        load.assert_called_once()
        html, path, metadata = render.call_args.args
        assert path == output
        assert "op.acc.2" in html and "mp.s.1" not in html
        assert metadata["title"] == "ENS RD2022 Report - ENS"

    def test_logs_and_reraises_render_errors(self, generator, mixed_data, tmp_path):
        with (
            patch.object(ens_module, "load_compliance_data", return_value=mixed_data),
            patch.object(ens_module, "render_pdf", side_effect=RuntimeError("boom")),
            patch.object(ens_module.logger, "exception") as log_exception,
            pytest.raises(RuntimeError),
        ):
            generator.generate(
                "t", "s", "ens_rd2022_aws", str(tmp_path / "ens.pdf"), "p"
            )

        assert "report_generation_failed" in log_exception.call_args.args[0]


def test_writes_a_real_pdf(mixed_data, tmp_path):
    from tasks.jobs.reports.html_renderer import render_pdf

    output = tmp_path / "ens.pdf"
    pages = render_pdf(
        render_html("ens.html.j2", build_ens_context(mixed_data)),
        str(output),
        {"title": "ENS", "subject": "ENS", "keywords": "ens"},
    )

    assert output.read_bytes().startswith(b"%PDF")
    assert pages >= 6
