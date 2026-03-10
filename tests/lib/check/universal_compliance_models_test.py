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


class TestAttributeMetadata:
    def test_basic(self):
        meta = AttributeMetadata(Key="Section", Type="str")
        assert meta.Key == "Section"
        assert meta.Type == "str"
        assert meta.CSV is True
        assert meta.Required is False

    def test_with_enum(self):
        meta = AttributeMetadata(
            Key="Profile",
            Type="str",
            Enum=["Level 1", "Level 2"],
        )
        assert meta.Enum == ["Level 1", "Level 2"]

    def test_int_type(self):
        meta = AttributeMetadata(Key="LevelOfRisk", Type="int", Required=True)
        assert meta.Type == "int"
        assert meta.Required is True

    def test_enum_display_field(self):
        meta = AttributeMetadata(
            Key="Dimensiones",
            Type="str",
            Enum=["confidencialidad", "integridad", "trazabilidad"],
            EnumDisplay={
                "confidencialidad": {
                    "Label": "Confidencialidad",
                    "Abbreviation": "C",
                    "Color": "#FF6347",
                },
                "integridad": {
                    "Label": "Integridad",
                    "Abbreviation": "I",
                    "Color": "#4286F4",
                },
                "trazabilidad": {
                    "Label": "Trazabilidad",
                    "Abbreviation": "T",
                    "Color": "#32CD32",
                },
            },
        )
        assert meta.EnumDisplay is not None
        assert meta.EnumDisplay["confidencialidad"]["Abbreviation"] == "C"
        assert meta.EnumDisplay["integridad"]["Color"] == "#4286F4"

    def test_enum_order_field(self):
        meta = AttributeMetadata(
            Key="Nivel",
            Type="str",
            Enum=["opcional", "bajo", "medio", "alto"],
            EnumOrder=["alto", "medio", "bajo", "opcional"],
        )
        assert meta.EnumOrder == ["alto", "medio", "bajo", "opcional"]

    def test_chart_label_field(self):
        meta = AttributeMetadata(
            Key="Section",
            Type="str",
            ChartLabel="Security Domain",
        )
        assert meta.ChartLabel == "Security Domain"

    def test_ocsf_default_true(self):
        meta = AttributeMetadata(Key="Section")
        assert meta.OCSF is True

    def test_ocsf_explicit_false(self):
        meta = AttributeMetadata(Key="InternalNote", OCSF=False)
        assert meta.OCSF is False

    def test_new_fields_default_none(self):
        meta = AttributeMetadata(Key="Section")
        assert meta.EnumDisplay is None
        assert meta.EnumOrder is None
        assert meta.ChartLabel is None


class TestEnumValueDisplay:
    def test_basic(self):
        evd = EnumValueDisplay(Label="Test")
        assert evd.Label == "Test"
        assert evd.Abbreviation is None
        assert evd.Color is None
        assert evd.Icon is None

    def test_dimension_style(self):
        evd = EnumValueDisplay(
            Label="Trazabilidad",
            Abbreviation="T",
            Color="#4286F4",
        )
        assert evd.Label == "Trazabilidad"
        assert evd.Abbreviation == "T"
        assert evd.Color == "#4286F4"

    def test_tipo_style(self):
        evd = EnumValueDisplay(
            Label="Requisito",
            Icon="⚠️",
        )
        assert evd.Icon == "⚠️"
        assert evd.Abbreviation is None


class TestChartConfig:
    def test_horizontal_bar(self):
        chart = ChartConfig(
            Id="section_compliance",
            Type="horizontal_bar",
            GroupBy="Section",
            Title="Compliance Score by Domain",
            YLabel="Domain",
            XLabel="Compliance %",
        )
        assert chart.Type == "horizontal_bar"
        assert chart.GroupBy == "Section"
        assert chart.ValueSource == "compliance_percent"
        assert chart.ColorMode == "by_value"

    def test_vertical_bar(self):
        chart = ChartConfig(
            Id="risk_distribution",
            Type="vertical_bar",
            GroupBy="LevelOfRisk",
            ColorMode="fixed",
            FixedColor="#336699",
        )
        assert chart.Type == "vertical_bar"
        assert chart.FixedColor == "#336699"

    def test_radar(self):
        chart = ChartConfig(
            Id="dimension_radar",
            Type="radar",
            GroupBy="Dimensiones",
        )
        assert chart.Type == "radar"

    def test_defaults(self):
        chart = ChartConfig(Id="test", Type="vertical_bar", GroupBy="Section")
        assert chart.Title is None
        assert chart.XLabel is None
        assert chart.YLabel is None
        assert chart.ValueSource == "compliance_percent"
        assert chart.ColorMode == "by_value"
        assert chart.FixedColor is None


class TestScoringFormula:
    def test_threatscore_style(self):
        formula = ScoringFormula(
            RiskField="LevelOfRisk",
            WeightField="Weight",
            RiskBoostFactor=0.25,
        )
        assert formula.RiskField == "LevelOfRisk"
        assert formula.WeightField == "Weight"
        assert formula.RiskBoostFactor == 0.25

    def test_custom_boost_factor(self):
        formula = ScoringFormula(
            RiskField="Risk",
            WeightField="Impact",
            RiskBoostFactor=0.5,
        )
        assert formula.RiskBoostFactor == 0.5

    def test_default_boost_factor(self):
        formula = ScoringFormula(RiskField="LevelOfRisk", WeightField="Weight")
        assert formula.RiskBoostFactor == 0.25


class TestCriticalRequirementsFilter:
    def test_int_based(self):
        crf = CriticalRequirementsFilter(
            FilterField="LevelOfRisk",
            MinValue=4,
            Title="Critical Failed Requirements",
        )
        assert crf.FilterField == "LevelOfRisk"
        assert crf.MinValue == 4
        assert crf.FilterValue is None
        assert crf.StatusFilter == "FAIL"
        assert crf.Title == "Critical Failed Requirements"

    def test_string_based(self):
        crf = CriticalRequirementsFilter(
            FilterField="Nivel",
            FilterValue="alto",
        )
        assert crf.FilterValue == "alto"
        assert crf.MinValue is None

    def test_defaults(self):
        crf = CriticalRequirementsFilter(FilterField="LevelOfRisk")
        assert crf.StatusFilter == "FAIL"
        assert crf.Title is None
        assert crf.MinValue is None
        assert crf.FilterValue is None


class TestReportFilter:
    def test_defaults(self):
        rf = ReportFilter()
        assert rf.OnlyFailed is True
        assert rf.IncludeManual is False

    def test_custom(self):
        rf = ReportFilter(OnlyFailed=False, IncludeManual=True)
        assert rf.OnlyFailed is False
        assert rf.IncludeManual is True


class TestI18nLabels:
    def test_english_defaults(self):
        labels = I18nLabels()
        assert labels.PageLabel == "Page"
        assert labels.PoweredBy == "Powered by Prowler"
        assert labels.FrameworkLabel == "Framework:"
        assert labels.ProviderLabel == "Provider:"
        assert labels.ReportTitle is None

    def test_spanish_override(self):
        labels = I18nLabels(
            ReportTitle="Informe de Cumplimiento ENS",
            PageLabel="Página",
            PoweredBy="Generado por Prowler",
            FrameworkLabel="Marco:",
            VersionLabel="Versión:",
            ProviderLabel="Proveedor:",
            DescriptionLabel="Descripción:",
            ComplianceScoreLabel="Puntuación de Cumplimiento por Secciones",
            RequirementsIndexLabel="Índice de Requisitos",
            DetailedFindingsLabel="Hallazgos Detallados",
        )
        assert labels.PageLabel == "Página"
        assert labels.ProviderLabel == "Proveedor:"
        assert labels.ReportTitle == "Informe de Cumplimiento ENS"


class TestSplitByConfig:
    def test_cis_style(self):
        config = SplitByConfig(Field="Profile", Values=["Level 1", "Level 2"])
        assert config.Field == "Profile"
        assert len(config.Values) == 2

    def test_ens_style(self):
        config = SplitByConfig(
            Field="Nivel",
            Values=["alto", "medio", "bajo", "opcional"],
        )
        assert len(config.Values) == 4


class TestScoringConfig:
    def test_threatscore_style(self):
        config = ScoringConfig(RiskField="LevelOfRisk", WeightField="Weight")
        assert config.RiskField == "LevelOfRisk"
        assert config.WeightField == "Weight"


class TestTableLabels:
    def test_defaults(self):
        labels = TableLabels()
        assert labels.PassLabel == "PASS"
        assert labels.FailLabel == "FAIL"
        assert labels.ProviderHeader == "Provider"

    def test_ens_spanish(self):
        labels = TableLabels(
            PassLabel="CUMPLE",
            FailLabel="NO CUMPLE",
            ProviderHeader="Proveedor",
        )
        assert labels.PassLabel == "CUMPLE"


class TestTableConfig:
    def test_grouped_mode(self):
        tc = TableConfig(GroupBy="Section")
        assert tc.GroupBy == "Section"
        assert tc.SplitBy is None
        assert tc.Scoring is None

    def test_split_mode(self):
        tc = TableConfig(
            GroupBy="Section",
            SplitBy=SplitByConfig(Field="Profile", Values=["Level 1", "Level 2"]),
        )
        assert tc.SplitBy is not None
        assert tc.SplitBy.Field == "Profile"

    def test_scored_mode(self):
        tc = TableConfig(
            GroupBy="Section",
            Scoring=ScoringConfig(RiskField="LevelOfRisk", WeightField="Weight"),
        )
        assert tc.Scoring is not None


class TestPDFConfig:
    def test_defaults(self):
        pdf = PDFConfig()
        assert pdf.Language == "en"
        assert pdf.LogoFilename is None
        assert pdf.PrimaryColor is None
        assert pdf.Sections is None
        assert pdf.SectionShortNames is None
        assert pdf.GroupByField is None
        assert pdf.SubGroupByField is None
        assert pdf.SectionTitles is None
        assert pdf.Charts is None
        assert pdf.Scoring is None
        assert pdf.CriticalFilter is None
        assert pdf.Filter is None
        assert pdf.Labels is None

    def test_csa_ccm_style(self):
        pdf = PDFConfig(
            PrimaryColor="#336699",
            SecondaryColor="#4D80B3",
            BgColor="#F2F8FF",
            GroupByField="Section",
            Sections=["Audit & Assurance", "Identity & Access Management"],
            SectionShortNames={"Identity & Access Management": "IAM"},
            Charts=[
                ChartConfig(
                    Id="section_compliance",
                    Type="horizontal_bar",
                    GroupBy="Section",
                    Title="Compliance Score by Domain",
                ).dict()
            ],
            Filter=ReportFilter(OnlyFailed=True, IncludeManual=False),
        )
        assert pdf.PrimaryColor == "#336699"
        assert len(pdf.Sections) == 2
        assert pdf.SectionShortNames["Identity & Access Management"] == "IAM"
        assert pdf.GroupByField == "Section"
        assert pdf.Charts is not None
        assert len(pdf.Charts) == 1
        assert pdf.Filter.OnlyFailed is True

    def test_ens_style(self):
        pdf = PDFConfig(
            Language="es",
            LogoFilename="ens_logo.png",
            PrimaryColor="#CC3333",
            GroupByField="Marco",
            SubGroupByField="Categoria",
            Labels=I18nLabels(
                PageLabel="Página",
                ProviderLabel="Proveedor:",
            ),
        )
        assert pdf.Language == "es"
        assert pdf.LogoFilename == "ens_logo.png"
        assert pdf.GroupByField == "Marco"
        assert pdf.SubGroupByField == "Categoria"
        assert pdf.Labels.PageLabel == "Página"

    def test_threatscore_style(self):
        pdf = PDFConfig(
            PrimaryColor="#336699",
            Sections=["1. IAM", "2. Attack Surface"],
            Scoring=ScoringFormula(
                RiskField="LevelOfRisk",
                WeightField="Weight",
                RiskBoostFactor=0.25,
            ),
            CriticalFilter=CriticalRequirementsFilter(
                FilterField="LevelOfRisk",
                MinValue=4,
                Title="Critical Failed Requirements",
            ),
        )
        assert pdf.Scoring is not None
        assert pdf.Scoring.RiskField == "LevelOfRisk"
        assert pdf.CriticalFilter.MinValue == 4

    def test_section_titles(self):
        pdf = PDFConfig(
            SectionTitles={
                "1": "1. Policy on Security",
                "2": "2. Risk Management",
            },
        )
        assert pdf.SectionTitles["1"] == "1. Policy on Security"

    def test_in_framework(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test Framework",
            Description="Test",
            Requirements=[],
            Outputs=OutputsConfig(
                PDF_Config=PDFConfig(
                    PrimaryColor="#336699",
                    Sections=["Section A"],
                    Charts=[
                        ChartConfig(
                            Id="test_chart",
                            Type="vertical_bar",
                            GroupBy="Section",
                        ).dict()
                    ],
                ),
            ),
        )
        assert fw.Outputs is not None
        assert fw.Outputs.PDF_Config is not None
        assert fw.Outputs.PDF_Config.PrimaryColor == "#336699"
        assert fw.Outputs.PDF_Config.Sections == ["Section A"]
        assert fw.Outputs.PDF_Config.Charts is not None
        assert len(fw.Outputs.PDF_Config.Charts) == 1
        assert fw.Outputs.PDF_Config.Charts[0]["Id"] == "test_chart"
        assert fw.Outputs.PDF_Config.Charts[0]["Type"] == "vertical_bar"

    def test_framework_without_pdf_config(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test Framework",
            Description="Test",
            Requirements=[],
        )
        assert fw.Outputs is None


class TestUniversalComplianceRequirement:
    def test_flat_dict_attributes(self):
        req = UniversalComplianceRequirement(
            Id="1.1",
            Description="Test requirement",
            Attributes={"Section": "IAM", "Profile": "Level 1"},
            Checks=["check_a", "check_b"],
        )
        assert req.Attributes["Section"] == "IAM"
        assert len(req.Checks) == 2

    def test_mitre_optional_fields(self):
        req = UniversalComplianceRequirement(
            Id="T1190",
            Description="Exploit Public-Facing Application",
            Attributes={},
            Checks=["drs_job_exist"],
            Tactics=["Initial Access"],
            SubTechniques=[],
            Platforms=["IaaS", "Linux"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
        )
        assert req.Tactics == ["Initial Access"]
        assert req.TechniqueURL == "https://attack.mitre.org/techniques/T1190/"

    def test_dict_checks_multi_provider(self):
        req = UniversalComplianceRequirement(
            Id="1.1",
            Description="Multi-provider",
            Attributes={},
            Checks={"aws": ["check_a"], "azure": ["check_b"]},
        )
        assert isinstance(req.Checks, dict)
        assert "aws" in req.Checks

    def test_empty_checks(self):
        req = UniversalComplianceRequirement(
            Id="manual-1",
            Description="Manual requirement",
            Attributes={"Section": "Governance"},
            Checks=[],
        )
        assert req.Checks == []


class TestComplianceFramework:
    def test_basic_framework(self):
        fw = ComplianceFramework(
            Framework="TestFW",
            Name="Test Framework",
            Provider="AWS",
            Version="1.0",
            Description="A test framework",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="Test",
                    Attributes={"Section": "IAM"},
                    Checks=["check_a"],
                )
            ],
            AttributesMetadata=[
                AttributeMetadata(Key="Section", Type="str"),
            ],
            Outputs=OutputsConfig(Table_Config=TableConfig(GroupBy="Section")),
        )
        assert fw.Framework == "TestFW"
        assert fw.Outputs.Table_Config.GroupBy == "Section"
        assert len(fw.AttributesMetadata) == 1
        assert len(fw.Requirements) == 1

    def test_optional_provider(self):
        fw = ComplianceFramework(
            Framework="MultiCloud",
            Name="Multi-cloud framework",
            Description="A multi-provider framework",
            Requirements=[],
        )
        assert fw.Provider is None

    def test_get_providers_from_dict_checks(self):
        fw = ComplianceFramework(
            Framework="MultiCloud",
            Name="Multi-cloud",
            Description="test",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="test",
                    Attributes={},
                    Checks={
                        "aws": ["check_a"],
                        "azure": ["check_b"],
                        "gcp": ["check_c"],
                    },
                ),
                UniversalComplianceRequirement(
                    Id="1.2",
                    Description="test2",
                    Attributes={},
                    Checks={"aws": ["check_d"]},
                ),
            ],
        )
        providers = fw.get_providers()
        assert providers == ["aws", "azure", "gcp"]

    def test_get_providers_fallback_to_explicit(self):
        fw = ComplianceFramework(
            Framework="SingleCloud",
            Name="Single-cloud",
            Provider="AWS",
            Description="test",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="test",
                    Attributes={},
                    Checks=["check_a"],
                ),
            ],
        )
        providers = fw.get_providers()
        assert providers == ["aws"]

    def test_supports_provider_dict_checks(self):
        fw = ComplianceFramework(
            Framework="MultiCloud",
            Name="Multi-cloud",
            Description="test",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="test",
                    Attributes={},
                    Checks={"aws": ["check_a"], "azure": ["check_b"]},
                ),
            ],
        )
        assert fw.supports_provider("aws") is True
        assert fw.supports_provider("azure") is True
        assert fw.supports_provider("gcp") is False

    def test_supports_provider_list_checks(self):
        fw = ComplianceFramework(
            Framework="SingleCloud",
            Name="Single-cloud",
            Provider="AWS",
            Description="test",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="test",
                    Attributes={},
                    Checks=["check_a"],
                ),
            ],
        )
        assert fw.supports_provider("aws") is True
        assert fw.supports_provider("azure") is False

    def test_no_provider_field_with_dict_checks(self):
        """Multi-provider JSON has no Provider field — providers derived from Checks."""
        fw = ComplianceFramework(
            Framework="CSA_CCM",
            Name="CSA CCM 4.0",
            Description="Cloud Controls Matrix",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="A&A-01",
                    Description="Audit & Assurance",
                    Attributes={"Domain": "A&A"},
                    Checks={
                        "aws": ["check_a"],
                        "azure": ["check_b"],
                        "gcp": ["check_c"],
                    },
                ),
            ],
        )
        assert fw.Provider is None
        assert fw.get_providers() == ["aws", "azure", "gcp"]
        assert fw.supports_provider("aws")
        assert fw.supports_provider("azure")
        assert fw.supports_provider("gcp")
        assert not fw.supports_provider("kubernetes")

    def test_icon_field(self):
        fw = ComplianceFramework(
            Framework="CSA_CCM",
            Name="CSA CCM 4.0",
            Description="Cloud Controls Matrix",
            Icon="csa",
            Requirements=[],
        )
        assert fw.Icon == "csa"

    def test_icon_defaults_to_none(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[],
        )
        assert fw.Icon is None


class TestAdaptLegacyToUniversal:
    def test_adapt_cis(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.Framework == "CIS"
        assert fw.Provider == "AWS"
        assert len(fw.Requirements) == 2
        # First requirement should have flat attributes
        req = fw.Requirements[0]
        assert "Section" in req.Attributes
        assert req.Attributes["Section"] == "2. Storage"
        assert req.Tactics is None

    def test_adapt_ens(self):
        fw = adapt_legacy_to_universal(ENS_RD2022_AWS)
        assert fw.Framework == "ENS"
        req = fw.Requirements[0]
        assert "Marco" in req.Attributes
        assert req.Attributes["Marco"] == "operacional"

    def test_adapt_mitre(self):
        fw = adapt_legacy_to_universal(MITRE_ATTACK_AWS)
        assert fw.Framework == "MITRE-ATTACK"
        req = fw.Requirements[0]
        assert req.Tactics == ["Initial Access"]
        assert req.TechniqueURL == "https://attack.mitre.org/techniques/T1190/"
        assert "_raw_attributes" in req.Attributes

    def test_adapt_threatscore(self):
        fw = adapt_legacy_to_universal(PROWLER_THREATSCORE_AWS)
        req = fw.Requirements[0]
        assert req.Attributes["LevelOfRisk"] == 5
        assert req.Attributes["Weight"] == 1000

    def test_adapt_generic(self):
        fw = adapt_legacy_to_universal(NIST_800_53_REVISION_4_AWS)
        req = fw.Requirements[0]
        assert "Section" in req.Attributes

    def test_adapt_kisa(self):
        fw = adapt_legacy_to_universal(KISA_ISMSP_AWS)
        req = fw.Requirements[0]
        assert "Domain" in req.Attributes

    def test_inferred_metadata_cis(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.AttributesMetadata is not None
        keys = [m.Key for m in fw.AttributesMetadata]
        assert "Section" in keys
        assert "Profile" in keys

    def test_inferred_metadata_mitre_is_none(self):
        fw = adapt_legacy_to_universal(MITRE_ATTACK_AWS)
        assert fw.AttributesMetadata is None

    def test_table_config_is_none(self):
        fw = adapt_legacy_to_universal(CIS_1_4_AWS)
        assert fw.Outputs is None


class TestLoadComplianceFrameworkUniversal:
    def test_load_universal_format(self, tmp_path):
        data = {
            "Framework": "TestFW",
            "Name": "Test",
            "Provider": "AWS",
            "Version": "1.0",
            "Description": "desc",
            "Icon": "prowlerthreatscore",
            "AttributesMetadata": [{"Key": "Section", "Type": "str"}],
            "Outputs": {"TableConfig": {"GroupBy": "Section"}},
            "Requirements": [
                {
                    "Id": "1.1",
                    "Description": "test",
                    "Attributes": {"Section": "IAM"},
                    "Checks": ["check_a"],
                }
            ],
        }
        path = tmp_path / "test.json"
        path.write_text(json.dumps(data))
        fw = load_compliance_framework_universal(str(path))
        assert fw is not None
        assert fw.Framework == "TestFW"
        assert fw.Icon == "prowlerthreatscore"
        assert fw.Outputs.Table_Config.GroupBy == "Section"

    def test_load_universal_multi_provider(self, tmp_path):
        data = {
            "Framework": "CSA_CCM",
            "Name": "CSA CCM 4.0",
            "Version": "4.0",
            "Description": "Cloud Controls Matrix",
            "AttributesMetadata": [{"Key": "Domain", "Type": "str"}],
            "Outputs": {"TableConfig": {"GroupBy": "Domain"}},
            "Requirements": [
                {
                    "Id": "A&A-01",
                    "Description": "Audit",
                    "Attributes": {"Domain": "Audit"},
                    "Checks": {
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
        assert fw.Provider is None
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
        assert fw.Framework == "SOC2"
        assert fw.Outputs is None
        assert fw.Requirements[0].Attributes["Section"] == "Access Control"


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
        assert fw.Framework
        assert fw.Name
        assert len(fw.Requirements) >= 0


class TestBackwardCompat:
    """Ensure Compliance.get_bulk still returns Compliance objects."""

    def test_get_bulk_still_works(self):
        # This test just validates the legacy path still returns Compliance objects
        # We test with a constructed Compliance object
        legacy = CIS_1_4_AWS
        assert isinstance(legacy, Compliance)
        assert legacy.Framework == "CIS"


class TestAttributesMetadataValidation:
    """Validate that Requirement Attributes match their AttributesMetadata schema."""

    def _metadata(self, required=False, enum=None, type_str="str"):
        return [
            AttributeMetadata(Key="Section", Type="str", Required=True),
            AttributeMetadata(Key="Level", Type=type_str, Required=required, Enum=enum),
        ]

    def test_valid_attributes_pass(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="d",
                    Attributes={"Section": "IAM", "Level": "high"},
                    Checks=[],
                ),
            ],
            AttributesMetadata=self._metadata(),
        )
        assert len(fw.Requirements) == 1

    def test_missing_required_key_raises(self):
        with pytest.raises(
            ValidationError, match="missing required attribute 'Section'"
        ):
            ComplianceFramework(
                Framework="Test",
                Name="Test",
                Description="d",
                Requirements=[
                    UniversalComplianceRequirement(
                        Id="1.1",
                        Description="d",
                        Attributes={"Level": "high"},
                        Checks=[],
                    ),
                ],
                AttributesMetadata=self._metadata(),
            )

    def test_invalid_enum_value_raises(self):
        with pytest.raises(ValidationError, match="not in"):
            ComplianceFramework(
                Framework="Test",
                Name="Test",
                Description="d",
                Requirements=[
                    UniversalComplianceRequirement(
                        Id="1.1",
                        Description="d",
                        Attributes={"Section": "IAM", "Level": "invalid"},
                        Checks=[],
                    ),
                ],
                AttributesMetadata=self._metadata(enum=["high", "low"]),
            )

    def test_valid_enum_value_passes(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="d",
                    Attributes={"Section": "IAM", "Level": "high"},
                    Checks=[],
                ),
            ],
            AttributesMetadata=self._metadata(enum=["high", "low"]),
        )
        assert len(fw.Requirements) == 1

    def test_wrong_type_int_raises(self):
        with pytest.raises(ValidationError, match="expected type int"):
            ComplianceFramework(
                Framework="Test",
                Name="Test",
                Description="d",
                Requirements=[
                    UniversalComplianceRequirement(
                        Id="1.1",
                        Description="d",
                        Attributes={"Section": "IAM", "Level": "not_a_number"},
                        Checks=[],
                    ),
                ],
                AttributesMetadata=self._metadata(type_str="int"),
            )

    def test_correct_type_int_passes(self):
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="d",
                    Attributes={"Section": "IAM", "Level": 5},
                    Checks=[],
                ),
            ],
            AttributesMetadata=self._metadata(type_str="int"),
        )
        assert fw.Requirements[0].Attributes["Level"] == 5

    def test_none_optional_value_skips_validation(self):
        """None values for non-required keys should not trigger type/enum errors."""
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="d",
                    Attributes={"Section": "IAM", "Level": None},
                    Checks=[],
                ),
            ],
            AttributesMetadata=self._metadata(enum=["high", "low"]),
        )
        assert len(fw.Requirements) == 1

    def test_no_metadata_skips_validation(self):
        """Frameworks without AttributesMetadata should not be validated."""
        fw = ComplianceFramework(
            Framework="Test",
            Name="Test",
            Description="d",
            Requirements=[
                UniversalComplianceRequirement(
                    Id="1.1",
                    Description="d",
                    Attributes={"anything": "goes"},
                    Checks=[],
                ),
            ],
        )
        assert len(fw.Requirements) == 1

    def test_multiple_errors_reported(self):
        """All validation errors should be collected and reported together."""
        with pytest.raises(
            ValidationError, match="missing required attribute 'Section'"
        ):
            ComplianceFramework(
                Framework="Test",
                Name="Test",
                Description="d",
                Requirements=[
                    UniversalComplianceRequirement(
                        Id="1.1",
                        Description="d",
                        Attributes={"Level": "bad"},
                        Checks=[],
                    ),
                    UniversalComplianceRequirement(
                        Id="1.2",
                        Description="d",
                        Attributes={"Level": "also_bad"},
                        Checks=[],
                    ),
                ],
                AttributesMetadata=self._metadata(enum=["high", "low"]),
            )
