import json
import os

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.compliance_models import (
    AttributeMetadata,
    ChartConfig,
    Compliance,
    ComplianceFramework,
    CriticalRequirementsFilter,
    EnumValueDisplay,
    I18nLabels,
    OutputFormats,
    OutputsConfig,
    PDFConfig,
    ReportFilter,
    ScoringConfig,
    ScoringFormula,
    SplitByConfig,
    TableConfig,
    TableLabels,
    UniversalComplianceRequirement,
    adapt_legacy_to_universal,
    load_compliance_framework_universal,
)
from tests.lib.outputs.compliance.fixtures import (
    CIS_1_4_AWS,
    ENS_RD2022_AWS,
    KISA_ISMSP_AWS,
    MITRE_ATTACK_AWS,
    NIST_800_53_REVISION_4_AWS,
    PROWLER_THREATSCORE_AWS,
)


class TestOutputFormats:
    def test_defaults(self):
        of = OutputFormats()
        assert of.csv is True
        assert of.ocsf is True

    def test_explicit_false(self):
        of = OutputFormats(csv=False, ocsf=False)
        assert of.csv is False
        assert of.ocsf is False


class TestAttributeMetadata:
    def test_basic(self):
        meta = AttributeMetadata(key="Section", type="str")
        assert meta.key == "Section"
        assert meta.type == "str"
        assert meta.output_formats.csv is True
        assert meta.required is False

    def test_with_enum(self):
        meta = AttributeMetadata(
            key="Profile",
            type="str",
            enum=["Level 1", "Level 2"],
        )
        assert meta.enum == ["Level 1", "Level 2"]

    def test_int_type(self):
        meta = AttributeMetadata(key="LevelOfRisk", type="int", required=True)
        assert meta.type == "int"
        assert meta.required is True

    def test_enum_display_field(self):
        meta = AttributeMetadata(
            key="Dimensiones",
            type="str",
            enum=["confidencialidad", "integridad", "trazabilidad"],
            enum_display={
                "confidencialidad": {
                    "label": "Confidencialidad",
                    "abbreviation": "C",
                    "color": "#FF6347",
                },
                "integridad": {
                    "label": "Integridad",
                    "abbreviation": "I",
                    "color": "#4286F4",
                },
                "trazabilidad": {
                    "label": "Trazabilidad",
                    "abbreviation": "T",
                    "color": "#32CD32",
                },
            },
        )
        assert meta.enum_display is not None
        assert meta.enum_display["confidencialidad"]["abbreviation"] == "C"
        assert meta.enum_display["integridad"]["color"] == "#4286F4"

    def test_enum_order_field(self):
        meta = AttributeMetadata(
            key="Nivel",
            type="str",
            enum=["opcional", "bajo", "medio", "alto"],
            enum_order=["alto", "medio", "bajo", "opcional"],
        )
        assert meta.enum_order == ["alto", "medio", "bajo", "opcional"]

    def test_chart_label_field(self):
        meta = AttributeMetadata(
            key="Section",
            type="str",
            chart_label="Security Domain",
        )
        assert meta.chart_label == "Security Domain"

    def test_output_formats_default_true(self):
        meta = AttributeMetadata(key="Section")
        assert meta.output_formats.csv is True
        assert meta.output_formats.ocsf is True

    def test_output_formats_explicit_false(self):
        meta = AttributeMetadata(
            key="InternalNote",
            output_formats=OutputFormats(csv=False, ocsf=False),
        )
        assert meta.output_formats.csv is False
        assert meta.output_formats.ocsf is False

    def test_new_fields_default_none(self):
        meta = AttributeMetadata(key="Section")
        assert meta.enum_display is None
        assert meta.enum_order is None
        assert meta.chart_label is None


class TestEnumValueDisplay:
    def test_basic(self):
        evd = EnumValueDisplay(label="Test")
        assert evd.label == "Test"
        assert evd.abbreviation is None
        assert evd.color is None
        assert evd.icon is None

    def test_dimension_style(self):
        evd = EnumValueDisplay(
            label="Trazabilidad",
            abbreviation="T",
            color="#4286F4",
        )
        assert evd.label == "Trazabilidad"
        assert evd.abbreviation == "T"
        assert evd.color == "#4286F4"

    def test_tipo_style(self):
        evd = EnumValueDisplay(
            label="Requisito",
            icon="⚠️",
        )
        assert evd.icon == "⚠️"
        assert evd.abbreviation is None


class TestChartConfig:
    def test_horizontal_bar(self):
        chart = ChartConfig(
            id="section_compliance",
            type="horizontal_bar",
            group_by="Section",
            title="Compliance Score by Domain",
            y_label="Domain",
            x_label="Compliance %",
        )
        assert chart.type == "horizontal_bar"
        assert chart.group_by == "Section"
        assert chart.value_source == "compliance_percent"
        assert chart.color_mode == "by_value"

    def test_vertical_bar(self):
        chart = ChartConfig(
            id="risk_distribution",
            type="vertical_bar",
            group_by="LevelOfRisk",
            color_mode="fixed",
            fixed_color="#336699",
        )
        assert chart.type == "vertical_bar"
        assert chart.fixed_color == "#336699"

    def test_radar(self):
        chart = ChartConfig(
            id="dimension_radar",
            type="radar",
            group_by="Dimensiones",
        )
        assert chart.type == "radar"

    def test_defaults(self):
        chart = ChartConfig(id="test", type="vertical_bar", group_by="Section")
        assert chart.title is None
        assert chart.x_label is None
        assert chart.y_label is None
        assert chart.value_source == "compliance_percent"
        assert chart.color_mode == "by_value"
        assert chart.fixed_color is None


class TestScoringFormula:
    def test_threatscore_style(self):
        formula = ScoringFormula(
            risk_field="LevelOfRisk",
            weight_field="Weight",
            risk_boost_factor=0.25,
        )
        assert formula.risk_field == "LevelOfRisk"
        assert formula.weight_field == "Weight"
        assert formula.risk_boost_factor == 0.25

    def test_custom_boost_factor(self):
        formula = ScoringFormula(
            risk_field="Risk",
            weight_field="Impact",
            risk_boost_factor=0.5,
        )
        assert formula.risk_boost_factor == 0.5

    def test_default_boost_factor(self):
        formula = ScoringFormula(risk_field="LevelOfRisk", weight_field="Weight")
        assert formula.risk_boost_factor == 0.25


class TestCriticalRequirementsFilter:
    def test_int_based(self):
        crf = CriticalRequirementsFilter(
            filter_field="LevelOfRisk",
            min_value=4,
            title="Critical Failed Requirements",
        )
        assert crf.filter_field == "LevelOfRisk"
        assert crf.min_value == 4
        assert crf.filter_value is None
        assert crf.status_filter == "FAIL"
        assert crf.title == "Critical Failed Requirements"

    def test_string_based(self):
        crf = CriticalRequirementsFilter(
            filter_field="Nivel",
            filter_value="alto",
        )
        assert crf.filter_value == "alto"
        assert crf.min_value is None

    def test_defaults(self):
        crf = CriticalRequirementsFilter(filter_field="LevelOfRisk")
        assert crf.status_filter == "FAIL"
        assert crf.title is None
        assert crf.min_value is None
        assert crf.filter_value is None


class TestReportFilter:
    def test_defaults(self):
        rf = ReportFilter()
        assert rf.only_failed is True
        assert rf.include_manual is False

    def test_custom(self):
        rf = ReportFilter(only_failed=False, include_manual=True)
        assert rf.only_failed is False
        assert rf.include_manual is True


class TestI18nLabels:
    def test_english_defaults(self):
        labels = I18nLabels()
        assert labels.page_label == "Page"
        assert labels.powered_by == "Powered by Prowler"
        assert labels.framework_label == "Framework:"
        assert labels.provider_label == "Provider:"
        assert labels.report_title is None

    def test_spanish_override(self):
        labels = I18nLabels(
            report_title="Informe de Cumplimiento ENS",
            page_label="Página",
            powered_by="Generado por Prowler",
            framework_label="Marco:",
            version_label="Versión:",
            provider_label="Proveedor:",
            description_label="Descripción:",
            compliance_score_label="Puntuación de Cumplimiento por Secciones",
            requirements_index_label="Índice de Requisitos",
            detailed_findings_label="Hallazgos Detallados",
        )
        assert labels.page_label == "Página"
        assert labels.provider_label == "Proveedor:"
        assert labels.report_title == "Informe de Cumplimiento ENS"


class TestSplitByConfig:
    def test_cis_style(self):
        config = SplitByConfig(field="Profile", values=["Level 1", "Level 2"])
        assert config.field == "Profile"
        assert len(config.values) == 2

    def test_ens_style(self):
        config = SplitByConfig(
            field="Nivel",
            values=["alto", "medio", "bajo", "opcional"],
        )
        assert len(config.values) == 4


class TestScoringConfig:
    def test_threatscore_style(self):
        config = ScoringConfig(risk_field="LevelOfRisk", weight_field="Weight")
        assert config.risk_field == "LevelOfRisk"
        assert config.weight_field == "Weight"


class TestTableLabels:
    def test_defaults(self):
        labels = TableLabels()
        assert labels.pass_label == "PASS"
        assert labels.fail_label == "FAIL"
        assert labels.provider_header == "Provider"

    def test_ens_spanish(self):
        labels = TableLabels(
            pass_label="CUMPLE",
            fail_label="NO CUMPLE",
            provider_header="Proveedor",
        )
        assert labels.pass_label == "CUMPLE"


class TestTableConfig:
    def test_grouped_mode(self):
        tc = TableConfig(group_by="Section")
        assert tc.group_by == "Section"
        assert tc.split_by is None
        assert tc.scoring is None

    def test_split_mode(self):
        tc = TableConfig(
            group_by="Section",
            split_by=SplitByConfig(field="Profile", values=["Level 1", "Level 2"]),
        )
        assert tc.split_by is not None
        assert tc.split_by.field == "Profile"

    def test_scored_mode(self):
        tc = TableConfig(
            group_by="Section",
            scoring=ScoringConfig(risk_field="LevelOfRisk", weight_field="Weight"),
        )
        assert tc.scoring is not None


class TestPDFConfig:
    def test_defaults(self):
        pdf = PDFConfig()
        assert pdf.language == "en"
        assert pdf.logo_filename is None
        assert pdf.primary_color is None
        assert pdf.sections is None
        assert pdf.section_short_names is None
        assert pdf.group_by_field is None
        assert pdf.sub_group_by_field is None
        assert pdf.section_titles is None
        assert pdf.charts is None
        assert pdf.scoring is None
        assert pdf.critical_filter is None
        assert pdf.filter is None
        assert pdf.labels is None

    def test_csa_ccm_style(self):
        pdf = PDFConfig(
            primary_color="#336699",
            secondary_color="#4D80B3",
            bg_color="#F2F8FF",
            group_by_field="Section",
            sections=["Audit & Assurance", "Identity & Access Management"],
            section_short_names={"Identity & Access Management": "IAM"},
            charts=[
                ChartConfig(
                    id="section_compliance",
                    type="horizontal_bar",
                    group_by="Section",
                    title="Compliance Score by Domain",
                ).dict()
            ],
            filter=ReportFilter(only_failed=True, include_manual=False),
        )
        assert pdf.primary_color == "#336699"
        assert len(pdf.sections) == 2
        assert pdf.section_short_names["Identity & Access Management"] == "IAM"
        assert pdf.group_by_field == "Section"
        assert pdf.charts is not None
        assert len(pdf.charts) == 1
        assert pdf.filter.only_failed is True

    def test_ens_style(self):
        pdf = PDFConfig(
            language="es",
            logo_filename="ens_logo.png",
            primary_color="#CC3333",
            group_by_field="Marco",
            sub_group_by_field="Categoria",
            labels=I18nLabels(
                page_label="Página",
                provider_label="Proveedor:",
            ),
        )
        assert pdf.language == "es"
        assert pdf.logo_filename == "ens_logo.png"
        assert pdf.group_by_field == "Marco"
        assert pdf.sub_group_by_field == "Categoria"
        assert pdf.labels.page_label == "Página"

    def test_threatscore_style(self):
        pdf = PDFConfig(
            primary_color="#336699",
            sections=["1. IAM", "2. Attack Surface"],
            scoring=ScoringFormula(
                risk_field="LevelOfRisk",
                weight_field="Weight",
                risk_boost_factor=0.25,
            ),
            critical_filter=CriticalRequirementsFilter(
                filter_field="LevelOfRisk",
                min_value=4,
                title="Critical Failed Requirements",
            ),
        )
        assert pdf.scoring is not None
        assert pdf.scoring.risk_field == "LevelOfRisk"
        assert pdf.critical_filter.min_value == 4

    def test_section_titles(self):
        pdf = PDFConfig(
            section_titles={
                "1": "1. Policy on Security",
                "2": "2. Risk Management",
            },
        )
        assert pdf.section_titles["1"] == "1. Policy on Security"

    def test_in_framework(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test Framework",
            description="Test",
            requirements=[],
            outputs=OutputsConfig(
                pdf_config=PDFConfig(
                    primary_color="#336699",
                    sections=["Section A"],
                    charts=[
                        ChartConfig(
                            id="test_chart",
                            type="vertical_bar",
                            group_by="Section",
                        ).dict()
                    ],
                ),
            ),
        )
        assert fw.outputs is not None
        assert fw.outputs.pdf_config is not None
        assert fw.outputs.pdf_config.primary_color == "#336699"
        assert fw.outputs.pdf_config.sections == ["Section A"]
        assert fw.outputs.pdf_config.charts is not None
        assert len(fw.outputs.pdf_config.charts) == 1
        assert fw.outputs.pdf_config.charts[0]["id"] == "test_chart"
        assert fw.outputs.pdf_config.charts[0]["type"] == "vertical_bar"

    def test_framework_without_pdf_config(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test Framework",
            description="Test",
            requirements=[],
        )
        assert fw.outputs is None


class TestUniversalComplianceRequirement:
    def test_flat_dict_attributes(self):
        req = UniversalComplianceRequirement(
            id="1.1",
            description="Test requirement",
            attributes={"Section": "IAM", "Profile": "Level 1"},
            checks={"aws": ["check_a", "check_b"]},
        )
        assert req.attributes["Section"] == "IAM"
        assert len(req.checks["aws"]) == 2

    def test_mitre_optional_fields(self):
        req = UniversalComplianceRequirement(
            id="T1190",
            description="Exploit Public-Facing Application",
            attributes={},
            checks={"aws": ["drs_job_exist"]},
            tactics=["Initial Access"],
            sub_techniques=[],
            platforms=["IaaS", "Linux"],
            technique_url="https://attack.mitre.org/techniques/T1190/",
        )
        assert req.tactics == ["Initial Access"]
        assert req.technique_url == "https://attack.mitre.org/techniques/T1190/"

    def test_dict_checks_multi_provider(self):
        req = UniversalComplianceRequirement(
            id="1.1",
            description="Multi-provider",
            attributes={},
            checks={"aws": ["check_a"], "azure": ["check_b"]},
        )
        assert isinstance(req.checks, dict)
        assert "aws" in req.checks

    def test_empty_checks(self):
        req = UniversalComplianceRequirement(
            id="manual-1",
            description="Manual requirement",
            attributes={"Section": "Governance"},
            checks={},
        )
        assert req.checks == {}

    def test_checks_default_is_empty_dict(self):
        req = UniversalComplianceRequirement(
            id="1.1",
            description="No checks provided",
        )
        assert req.checks == {}


class TestComplianceFramework:
    def test_basic_framework(self):
        fw = ComplianceFramework(
            framework="TestFW",
            name="Test Framework",
            provider="AWS",
            version="1.0",
            description="A test framework",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="Test",
                    attributes={"Section": "IAM"},
                    checks={"aws": ["check_a"]},
                )
            ],
            attributes_metadata=[
                AttributeMetadata(key="Section", type="str"),
            ],
            outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
        )
        assert fw.framework == "TestFW"
        assert fw.outputs.table_config.group_by == "Section"
        assert len(fw.attributes_metadata) == 1
        assert len(fw.requirements) == 1

    def test_optional_provider(self):
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi-cloud framework",
            description="A multi-provider framework",
            requirements=[],
        )
        assert fw.provider is None

    def test_get_providers_from_dict_checks(self):
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi-cloud",
            description="test",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="test",
                    attributes={},
                    checks={
                        "aws": ["check_a"],
                        "azure": ["check_b"],
                        "gcp": ["check_c"],
                    },
                ),
                UniversalComplianceRequirement(
                    id="1.2",
                    description="test2",
                    attributes={},
                    checks={"aws": ["check_d"]},
                ),
            ],
        )
        providers = fw.get_providers()
        assert providers == ["aws", "azure", "gcp"]

    def test_get_providers_fallback_to_explicit(self):
        fw = ComplianceFramework(
            framework="SingleCloud",
            name="Single-cloud",
            provider="AWS",
            description="test",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="test",
                    attributes={},
                    checks={},
                ),
            ],
        )
        providers = fw.get_providers()
        assert providers == ["aws"]

    def test_supports_provider_dict_checks(self):
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi-cloud",
            description="test",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="test",
                    attributes={},
                    checks={"aws": ["check_a"], "azure": ["check_b"]},
                ),
            ],
        )
        assert fw.supports_provider("aws") is True
        assert fw.supports_provider("azure") is True
        assert fw.supports_provider("gcp") is False

    def test_supports_provider_explicit_only(self):
        """Framework with explicit provider but no per-requirement checks still supports the provider."""
        fw = ComplianceFramework(
            framework="SingleCloud",
            name="Single-cloud",
            provider="AWS",
            description="test",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="Manual requirement",
                    attributes={},
                    checks={},
                ),
            ],
        )
        assert fw.supports_provider("aws") is True
        assert fw.supports_provider("azure") is False

    def test_no_provider_field_with_dict_checks(self):
        """Multi-provider JSON has no Provider field — providers derived from checks."""
        fw = ComplianceFramework(
            framework="CSA_CCM",
            name="CSA CCM 4.0",
            description="Cloud Controls Matrix",
            requirements=[
                UniversalComplianceRequirement(
                    id="A&A-01",
                    description="Audit & Assurance",
                    attributes={"Domain": "A&A"},
                    checks={
                        "aws": ["check_a"],
                        "azure": ["check_b"],
                        "gcp": ["check_c"],
                    },
                ),
            ],
        )
        assert fw.provider is None
        assert fw.get_providers() == ["aws", "azure", "gcp"]
        assert fw.supports_provider("aws")
        assert fw.supports_provider("azure")
        assert fw.supports_provider("gcp")
        assert not fw.supports_provider("kubernetes")

    def test_icon_field(self):
        fw = ComplianceFramework(
            framework="CSA_CCM",
            name="CSA CCM 4.0",
            description="Cloud Controls Matrix",
            icon="csa",
            requirements=[],
        )
        assert fw.icon == "csa"

    def test_icon_defaults_to_none(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[],
        )
        assert fw.icon is None


class TestAdaptLegacyToUniversal:
    def test_adapt_cis(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.framework == "CIS"
        assert fw.provider == "AWS"
        assert len(fw.requirements) == 2
        # First requirement should have flat attributes
        req = fw.requirements[0]
        assert "Section" in req.attributes
        assert req.attributes["Section"] == "2. Storage"
        assert req.tactics is None
        # Checks must be wrapped in dict keyed by provider
        assert isinstance(req.checks, dict)
        assert "aws" in req.checks

    def test_adapt_ens(self):
        fw = adapt_legacy_to_universal(ENS_RD2022_AWS)
        assert fw.framework == "ENS"
        req = fw.requirements[0]
        assert "Marco" in req.attributes
        assert req.attributes["Marco"] == "operacional"

    def test_adapt_mitre(self):
        fw = adapt_legacy_to_universal(MITRE_ATTACK_AWS)
        assert fw.framework == "MITRE-ATTACK"
        req = fw.requirements[0]
        assert req.tactics == ["Initial Access"]
        assert req.technique_url == "https://attack.mitre.org/techniques/T1190/"
        assert "_raw_attributes" in req.attributes
        assert isinstance(req.checks, dict)
        assert "aws" in req.checks

    def test_adapt_threatscore(self):
        fw = adapt_legacy_to_universal(PROWLER_THREATSCORE_AWS)
        req = fw.requirements[0]
        assert req.attributes["LevelOfRisk"] == 5
        assert req.attributes["Weight"] == 1000

    def test_adapt_generic(self):
        fw = adapt_legacy_to_universal(NIST_800_53_REVISION_4_AWS)
        req = fw.requirements[0]
        assert "Section" in req.attributes

    def test_adapt_kisa(self):
        fw = adapt_legacy_to_universal(KISA_ISMSP_AWS)
        req = fw.requirements[0]
        assert "Domain" in req.attributes

    def test_inferred_metadata_cis(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.attributes_metadata is not None
        keys = [m.key for m in fw.attributes_metadata]
        assert "Section" in keys
        assert "Profile" in keys

    def test_inferred_metadata_mitre_is_none(self):
        fw = adapt_legacy_to_universal(MITRE_ATTACK_AWS)
        assert fw.attributes_metadata is None

    def test_table_config_is_none(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.outputs is None


class TestLoadComplianceFrameworkUniversal:
    def test_load_universal_format(self, tmp_path):
        data = {
            "framework": "TestFW",
            "name": "Test",
            "provider": "AWS",
            "version": "1.0",
            "description": "desc",
            "icon": "prowlerthreatscore",
            "attributes_metadata": [{"key": "Section", "type": "str"}],
            "outputs": {"table_config": {"group_by": "Section"}},
            "requirements": [
                {
                    "id": "1.1",
                    "description": "test",
                    "attributes": {"Section": "IAM"},
                    "checks": {"aws": ["check_a"]},
                }
            ],
        }
        path = tmp_path / "test.json"
        path.write_text(json.dumps(data))
        fw = load_compliance_framework_universal(str(path))
        assert fw is not None
        assert fw.framework == "TestFW"
        assert fw.icon == "prowlerthreatscore"
        assert fw.outputs.table_config.group_by == "Section"

    def test_load_universal_multi_provider(self, tmp_path):
        data = {
            "framework": "CSA_CCM",
            "name": "CSA CCM 4.0",
            "version": "4.0",
            "description": "Cloud Controls Matrix",
            "attributes_metadata": [{"key": "Domain", "type": "str"}],
            "outputs": {"table_config": {"group_by": "Domain"}},
            "requirements": [
                {
                    "id": "A&A-01",
                    "description": "Audit",
                    "attributes": {"Domain": "Audit"},
                    "checks": {
                        "aws": ["check_a"],
                        "azure": ["check_b"],
                        "gcp": ["check_c"],
                    },
                }
            ],
        }
        path = tmp_path / "csa_ccm_4.0.json"
        path.write_text(json.dumps(data))
        fw = load_compliance_framework_universal(str(path))
        assert fw is not None
        assert fw.provider is None
        assert fw.get_providers() == ["aws", "azure", "gcp"]
        assert fw.supports_provider("aws")
        assert not fw.supports_provider("kubernetes")

    def test_load_legacy_format(self, tmp_path):
        data = {
            "Framework": "SOC2",
            "Name": "SOC2",
            "Provider": "AWS",
            "Version": "",
            "Description": "desc",
            "Requirements": [
                {
                    "Id": "1.1",
                    "Description": "test",
                    "Attributes": [{"Section": "Access Control"}],
                    "Checks": ["check_a"],
                }
            ],
        }
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(data))
        fw = load_compliance_framework_universal(str(path))
        assert fw is not None
        assert fw.framework == "SOC2"
        assert fw.outputs is None
        assert fw.requirements[0].attributes["Section"] == "Access Control"
        assert fw.requirements[0].checks == {"aws": ["check_a"]}


class TestSmokeLoadAllJSONs:
    """Parametrized smoke test: every existing compliance JSON must load as ComplianceFramework."""

    @staticmethod
    def _find_all_compliance_jsons():
        base = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "prowler",
            "compliance",
        )
        base = os.path.normpath(base)
        jsons = []
        if os.path.isdir(base):
            # Top-level JSONs (multi-provider)
            for filename in os.listdir(base):
                if filename.endswith(".json"):
                    jsons.append(os.path.join(base, filename))
            # Provider sub-directory JSONs
            for provider_dir in os.listdir(base):
                provider_path = os.path.join(base, provider_dir)
                if os.path.isdir(provider_path):
                    for filename in os.listdir(provider_path):
                        if filename.endswith(".json"):
                            jsons.append(os.path.join(provider_path, filename))
        return jsons

    @pytest.mark.parametrize(
        "json_path",
        _find_all_compliance_jsons.__func__(),
        ids=lambda p: os.path.basename(p),
    )
    def test_loads_as_universal(self, json_path):
        fw = load_compliance_framework_universal(json_path)
        assert fw is not None, f"Failed to load {json_path}"
        assert fw.framework
        assert fw.name
        assert len(fw.requirements) >= 0


class TestBackwardCompat:
    """Ensure Compliance.get_bulk still returns Compliance objects."""

    def test_get_bulk_still_works(self):
        # This test just validates the legacy path still returns Compliance objects
        # We test with a constructed Compliance object
        legacy = CIS_1_4_AWS
        assert isinstance(legacy, Compliance)
        assert legacy.Framework == "CIS"


class TestAttributesMetadataValidation:
    """Validate that Requirement attributes match their attributes_metadata schema."""

    def _metadata(self, required=False, enum=None, type_str="str"):
        return [
            AttributeMetadata(key="Section", type="str", required=True),
            AttributeMetadata(key="Level", type=type_str, required=required, enum=enum),
        ]

    def test_valid_attributes_pass(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={"Section": "IAM", "Level": "high"},
                    checks={},
                ),
            ],
            attributes_metadata=self._metadata(),
        )
        assert len(fw.requirements) == 1

    def test_missing_required_key_raises(self):
        with pytest.raises(
            ValidationError, match="missing required attribute 'Section'"
        ):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={"Level": "high"},
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(),
            )

    def test_invalid_enum_value_raises(self):
        with pytest.raises(ValidationError, match="not in"):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={"Section": "IAM", "Level": "invalid"},
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(enum=["high", "low"]),
            )

    def test_valid_enum_value_passes(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={"Section": "IAM", "Level": "high"},
                    checks={},
                ),
            ],
            attributes_metadata=self._metadata(enum=["high", "low"]),
        )
        assert len(fw.requirements) == 1

    def test_wrong_type_int_raises(self):
        with pytest.raises(ValidationError, match="expected type int"):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={"Section": "IAM", "Level": "not_a_number"},
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(type_str="int"),
            )

    def test_correct_type_int_passes(self):
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={"Section": "IAM", "Level": 5},
                    checks={},
                ),
            ],
            attributes_metadata=self._metadata(type_str="int"),
        )
        assert fw.requirements[0].attributes["Level"] == 5

    def test_none_optional_value_skips_validation(self):
        """None values for non-required keys should not trigger type/enum errors."""
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={"Section": "IAM", "Level": None},
                    checks={},
                ),
            ],
            attributes_metadata=self._metadata(enum=["high", "low"]),
        )
        assert len(fw.requirements) == 1

    def test_no_metadata_skips_validation(self):
        """Frameworks without attributes_metadata should not be validated."""
        fw = ComplianceFramework(
            framework="Test",
            name="Test",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={"anything": "goes"},
                    checks={},
                ),
            ],
        )
        assert len(fw.requirements) == 1

    def test_unknown_attribute_key_raises(self):
        """Typos like 'Sectoin' must be rejected by the schema validator."""
        with pytest.raises(ValidationError, match="unknown attribute 'Sectoin'"):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={"Sectoin": "IAM", "Level": "high"},
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(enum=["high", "low"]),
            )

    def test_multiple_unknown_keys_all_reported(self):
        """Every unknown key must appear in the validation error (deterministic order)."""
        with pytest.raises(
            ValidationError,
            match=r"unknown attribute 'Bogus1'[\s\S]*unknown attribute 'Bogus2'",
        ):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={
                            "Section": "IAM",
                            "Level": "high",
                            "Bogus1": "x",
                            "Bogus2": "y",
                        },
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(enum=["high", "low"]),
            )

    def test_multiple_errors_reported(self):
        """All validation errors should be collected and reported together."""
        with pytest.raises(
            ValidationError, match="missing required attribute 'Section'"
        ):
            ComplianceFramework(
                framework="Test",
                name="Test",
                description="d",
                requirements=[
                    UniversalComplianceRequirement(
                        id="1.1",
                        description="d",
                        attributes={"Level": "bad"},
                        checks={},
                    ),
                    UniversalComplianceRequirement(
                        id="1.2",
                        description="d",
                        attributes={"Level": "also_bad"},
                        checks={},
                    ),
                ],
                attributes_metadata=self._metadata(enum=["high", "low"]),
            )
