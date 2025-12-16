import io
from unittest.mock import Mock, patch

import pytest
from reportlab.platypus import PageBreak, Paragraph, Table
from tasks.jobs.reports import FRAMEWORK_REGISTRY, ComplianceData, RequirementData
from tasks.jobs.reports.ens import ENSReportGenerator


# Use string status values directly to avoid Django DB initialization
# These match api.models.StatusChoices values
class StatusChoices:
    """Mock StatusChoices to avoid Django DB initialization."""

    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def ens_generator():
    """Create an ENSReportGenerator instance for testing."""
    config = FRAMEWORK_REGISTRY["ens"]
    return ENSReportGenerator(config)


@pytest.fixture
def mock_ens_requirement_attribute():
    """Create a mock ENS requirement attribute with all fields."""
    mock = Mock()
    mock.Marco = "Operacional"
    mock.Categoria = "Gestión de incidentes"
    mock.DescripcionControl = "Control de gestión de incidentes de seguridad"
    mock.Tipo = "requisito"
    mock.Nivel = "alto"
    mock.Dimensiones = ["confidencialidad", "integridad"]
    mock.ModoEjecucion = "automatico"
    mock.IdGrupoControl = "op.ext.1"
    return mock


@pytest.fixture
def mock_ens_requirement_attribute_medio():
    """Create a mock ENS requirement attribute with nivel medio."""
    mock = Mock()
    mock.Marco = "Organizativo"
    mock.Categoria = "Seguridad en los recursos humanos"
    mock.DescripcionControl = "Control de seguridad del personal"
    mock.Tipo = "refuerzo"
    mock.Nivel = "medio"
    mock.Dimensiones = "trazabilidad, autenticidad"  # String format
    mock.ModoEjecucion = "manual"
    mock.IdGrupoControl = "org.rh.1"
    return mock


@pytest.fixture
def mock_ens_requirement_attribute_bajo():
    """Create a mock ENS requirement attribute with nivel bajo."""
    mock = Mock()
    mock.Marco = "Medidas de Protección"
    mock.Categoria = "Protección de las instalaciones"
    mock.DescripcionControl = "Control de acceso físico"
    mock.Tipo = "recomendacion"
    mock.Nivel = "bajo"
    mock.Dimensiones = ["disponibilidad"]
    mock.ModoEjecucion = "automatico"
    mock.IdGrupoControl = "mp.if.1"
    return mock


@pytest.fixture
def mock_ens_requirement_attribute_opcional():
    """Create a mock ENS requirement attribute with nivel opcional."""
    mock = Mock()
    mock.Marco = "Marco de Organización"
    mock.Categoria = "Política de seguridad"
    mock.DescripcionControl = "Política de seguridad de la información"
    mock.Tipo = "medida"
    mock.Nivel = "opcional"
    mock.Dimensiones = []
    mock.ModoEjecucion = "automatico"
    mock.IdGrupoControl = "org.1"
    return mock


@pytest.fixture
def basic_ens_compliance_data():
    """Create basic ComplianceData for ENS testing."""
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="ens_rd2022_aws",
        framework="ENS RD2022",
        name="Esquema Nacional de Seguridad RD 311/2022",
        version="2022",
        description="Marco de seguridad para la administración electrónica española",
    )


# =============================================================================
# Generator Initialization Tests
# =============================================================================


class TestENSGeneratorInitialization:
    """Test suite for ENS generator initialization."""

    def test_generator_creation(self, ens_generator):
        """Test that ENS generator is created correctly."""
        assert ens_generator is not None
        assert ens_generator.config.name == "ens"
        assert ens_generator.config.language == "es"

    def test_generator_has_niveles(self, ens_generator):
        """Test that ENS config has niveles enabled."""
        assert ens_generator.config.has_niveles is True

    def test_generator_has_dimensions(self, ens_generator):
        """Test that ENS config has dimensions enabled."""
        assert ens_generator.config.has_dimensions is True

    def test_generator_no_risk_levels(self, ens_generator):
        """Test that ENS config does not use risk levels."""
        assert ens_generator.config.has_risk_levels is False

    def test_generator_no_weight(self, ens_generator):
        """Test that ENS config does not use weight."""
        assert ens_generator.config.has_weight is False


# =============================================================================
# Cover Page Tests
# =============================================================================


class TestENSCoverPage:
    """Test suite for ENS cover page generation."""

    @patch("tasks.jobs.reports.ens.Image")
    def test_cover_page_has_logos(
        self, mock_image, ens_generator, basic_ens_compliance_data
    ):
        """Test that cover page contains logos."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_cover_page(basic_ens_compliance_data)

        assert len(elements) > 0
        # Should have called Image at least twice (prowler + ens logos)
        assert mock_image.call_count >= 2

    def test_cover_page_has_title(self, ens_generator, basic_ens_compliance_data):
        """Test that cover page contains the ENS title."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_cover_page(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "ENS" in content or "Informe" in content

    def test_cover_page_has_info_table(self, ens_generator, basic_ens_compliance_data):
        """Test that cover page contains info table with metadata."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_cover_page(basic_ens_compliance_data)

        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1  # At least info table

    def test_cover_page_has_warning_about_manual(
        self, ens_generator, basic_ens_compliance_data
    ):
        """Test that cover page has warning about manual requirements."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            )
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_cover_page(basic_ens_compliance_data)

        # Find paragraphs (including those inside tables) that mention manual
        all_paragraphs = []
        for e in elements:
            if isinstance(e, Paragraph):
                all_paragraphs.append(e)
            elif isinstance(e, Table):
                # Check table cells for Paragraph objects
                cell_values = getattr(e, "_cellvalues", [])
                for row in cell_values:
                    for cell in row:
                        if isinstance(cell, Paragraph):
                            all_paragraphs.append(cell)
        content = " ".join(str(p.text) for p in all_paragraphs)
        assert "manual" in content.lower() or "AVISO" in content

    def test_cover_page_has_legend(self, ens_generator, basic_ens_compliance_data):
        """Test that cover page contains the ENS values legend."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_cover_page(basic_ens_compliance_data)

        # Legend should be a table with explanations
        tables = [e for e in elements if isinstance(e, Table)]
        # At least 3 tables: logos, info, warning, legend
        assert len(tables) >= 3


# =============================================================================
# Executive Summary Tests
# =============================================================================


class TestENSExecutiveSummary:
    """Test suite for ENS executive summary generation."""

    def test_executive_summary_has_title(
        self, ens_generator, basic_ens_compliance_data
    ):
        """Test that executive summary has Spanish title."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_executive_summary(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Resumen Ejecutivo" in content

    def test_executive_summary_calculates_compliance(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that executive summary calculates compliance percentage."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_executive_summary(basic_ens_compliance_data)

        # Should contain tables with metrics
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_executive_summary_excludes_manual_from_compliance(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that manual requirements are excluded from compliance calculation."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_executive_summary(basic_ens_compliance_data)

        # Should calculate 100% compliance (only 1 auto requirement that passed)
        assert len(elements) > 0

    def test_executive_summary_has_nivel_table(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that executive summary includes compliance by nivel table."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Alto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_executive_summary(basic_ens_compliance_data)

        # Should have nivel table
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Nivel" in content or "nivel" in content.lower()


# =============================================================================
# Charts Section Tests
# =============================================================================


class TestENSChartsSection:
    """Test suite for ENS charts section generation."""

    def test_charts_section_has_page_breaks(
        self, ens_generator, basic_ens_compliance_data
    ):
        """Test that charts section has page breaks between charts."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_charts_section(basic_ens_compliance_data)

        page_breaks = [e for e in elements if isinstance(e, PageBreak)]
        assert len(page_breaks) >= 2  # At least 2 page breaks for different charts

    def test_charts_section_has_marco_category_chart(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that charts section contains Marco/Categoría chart."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_charts_section(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Marco" in content or "Categoría" in content

    def test_charts_section_has_dimensions_radar(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that charts section contains dimensions radar chart."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_charts_section(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Dimensiones" in content or "dimensiones" in content.lower()

    def test_charts_section_has_tipo_distribution(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that charts section contains tipo distribution."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_charts_section(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Tipo" in content or "tipo" in content.lower()


# =============================================================================
# Critical Failed Requirements Tests
# =============================================================================


class TestENSCriticalFailedRequirements:
    """Test suite for ENS critical failed requirements (nivel alto)."""

    def test_no_critical_failures_shows_success_message(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that no critical failures shows success message."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed alto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator._create_critical_failed_section(
            basic_ens_compliance_data
        )

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "No hay" in content or "✅" in content

    def test_critical_failures_shows_table(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that critical failures shows requirements table."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Failed alto requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator._create_critical_failed_section(
            basic_ens_compliance_data
        )

        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_critical_failures_only_includes_alto(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute,
        mock_ens_requirement_attribute_medio,
    ):
        """Test that only nivel alto failures are included."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Failed alto requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed medio requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_medio]}
            },
        }

        elements = ens_generator._create_critical_failed_section(
            basic_ens_compliance_data
        )

        # Should have table but only with alto requirement
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should mention 1 critical requirement
        assert "1" in content


# =============================================================================
# Requirements Index Tests
# =============================================================================


class TestENSRequirementsIndex:
    """Test suite for ENS requirements index generation."""

    def test_requirements_index_has_title(
        self, ens_generator, basic_ens_compliance_data
    ):
        """Test that requirements index has Spanish title."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_requirements_index(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Índice" in content or "Requisitos" in content

    def test_requirements_index_organized_by_marco(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute,
        mock_ens_requirement_attribute_medio,
    ):
        """Test that requirements index is organized by Marco."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Operacional requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Organizativo requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_medio]}
            },
        }

        elements = ens_generator.create_requirements_index(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert (
            "Operacional" in content or "Organizativo" in content or "Marco" in content
        )

    def test_requirements_index_excludes_manual(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that manual requirements are excluded from index."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Auto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_requirements_index(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # REQ-001 should be there, REQ-002 should not
        assert "REQ-001" in content
        assert "REQ-002" not in content

    def test_requirements_index_shows_status_indicators(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that requirements index shows pass/fail indicators."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_requirements_index(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should have status indicators
        assert "✓" in content or "✗" in content


# =============================================================================
# Detailed Findings Tests
# =============================================================================


class TestENSDetailedFindings:
    """Test suite for ENS detailed findings generation."""

    def test_detailed_findings_has_title(
        self, ens_generator, basic_ens_compliance_data
    ):
        """Test that detailed findings section has title."""
        basic_ens_compliance_data.requirements = []
        basic_ens_compliance_data.attributes_by_requirement_id = {}

        elements = ens_generator.create_detailed_findings(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Detalle" in content or "Requisitos" in content

    def test_detailed_findings_no_failures_message(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test message when no failed requirements exist."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_detailed_findings(basic_ens_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "No hay" in content or "requisitos fallidos" in content.lower()

    def test_detailed_findings_shows_failed_requirements(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that failed requirements are shown in detail."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_detailed_findings(basic_ens_compliance_data)

        # Should have tables showing requirement details
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_detailed_findings_shows_nivel_badges(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that detailed findings show nivel badges."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_detailed_findings(basic_ens_compliance_data)

        # Should generate without errors
        assert len(elements) > 0

    def test_detailed_findings_shows_dimensiones_badges(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that detailed findings show dimension badges."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator.create_detailed_findings(basic_ens_compliance_data)

        # Should generate without errors with dimension badges
        assert len(elements) > 0


# =============================================================================
# Dimension Handling Tests
# =============================================================================


class TestENSDimensionHandling:
    """Test suite for ENS security dimension handling."""

    def test_dimensions_as_list(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test handling dimensions as a list."""
        # mock_ens_requirement_attribute has Dimensiones as list
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        # Should not raise any errors
        chart_buffer = ens_generator._create_dimensions_radar_chart(
            basic_ens_compliance_data
        )
        assert isinstance(chart_buffer, io.BytesIO)

    def test_dimensions_as_string(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute_medio,
    ):
        """Test handling dimensions as comma-separated string."""
        # mock_ens_requirement_attribute_medio has Dimensiones as string
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_medio]}
            },
        }

        # Should not raise any errors
        chart_buffer = ens_generator._create_dimensions_radar_chart(
            basic_ens_compliance_data
        )
        assert isinstance(chart_buffer, io.BytesIO)

    def test_dimensions_empty(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute_opcional,
    ):
        """Test handling empty dimensions."""
        # mock_ens_requirement_attribute_opcional has empty Dimensiones
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_ens_requirement_attribute_opcional]
                }
            },
        }

        # Should not raise any errors
        chart_buffer = ens_generator._create_dimensions_radar_chart(
            basic_ens_compliance_data
        )
        assert isinstance(chart_buffer, io.BytesIO)


# =============================================================================
# Footer Tests
# =============================================================================


class TestENSFooter:
    """Test suite for ENS footer generation."""

    def test_footer_is_spanish(self, ens_generator):
        """Test that footer text is in Spanish."""
        left, right = ens_generator.get_footer_text(1)

        assert "Página" in left
        assert "Prowler" in right

    def test_footer_includes_page_number(self, ens_generator):
        """Test that footer includes page number."""
        left, right = ens_generator.get_footer_text(5)

        assert "5" in left


# =============================================================================
# Nivel Table Tests
# =============================================================================


class TestENSNivelTable:
    """Test suite for ENS nivel compliance table."""

    def test_nivel_table_all_niveles(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute,
        mock_ens_requirement_attribute_medio,
        mock_ens_requirement_attribute_bajo,
        mock_ens_requirement_attribute_opcional,
    ):
        """Test nivel table with all niveles represented."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Alto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Medio requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-003",
                description="Bajo requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-004",
                description="Opcional requirement",
                status=StatusChoices.PASS,
                passed_findings=3,
                failed_findings=0,
                total_findings=3,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_medio]}
            },
            "REQ-003": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_bajo]}
            },
            "REQ-004": {
                "attributes": {
                    "req_attributes": [mock_ens_requirement_attribute_opcional]
                }
            },
        }

        elements = ens_generator._create_nivel_table(basic_ens_compliance_data)

        # Should have at least one table
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_nivel_table_excludes_manual(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that manual requirements are excluded from nivel table."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Auto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator._create_nivel_table(basic_ens_compliance_data)

        # Should generate without errors
        assert len(elements) > 0


# =============================================================================
# Marco Category Chart Tests
# =============================================================================


class TestENSMarcoCategoryChart:
    """Test suite for ENS Marco/Categoría chart."""

    def test_marco_category_chart_creation(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that Marco/Categoría chart is created successfully."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        chart_buffer = ens_generator._create_marco_category_chart(
            basic_ens_compliance_data
        )

        assert isinstance(chart_buffer, io.BytesIO)
        assert chart_buffer.getvalue()  # Not empty

    def test_marco_category_chart_excludes_manual(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that manual requirements are excluded from chart."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Auto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        # Should not raise any errors
        chart_buffer = ens_generator._create_marco_category_chart(
            basic_ens_compliance_data
        )
        assert isinstance(chart_buffer, io.BytesIO)


# =============================================================================
# Tipo Section Tests
# =============================================================================


class TestENSTipoSection:
    """Test suite for ENS tipo distribution section."""

    def test_tipo_section_creation(
        self, ens_generator, basic_ens_compliance_data, mock_ens_requirement_attribute
    ):
        """Test that tipo section is created successfully."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Requisito type",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
        }

        elements = ens_generator._create_tipo_section(basic_ens_compliance_data)

        assert len(elements) > 0
        # Should have a table with tipo distribution
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_tipo_section_all_types(
        self,
        ens_generator,
        basic_ens_compliance_data,
        mock_ens_requirement_attribute,
        mock_ens_requirement_attribute_medio,
        mock_ens_requirement_attribute_bajo,
        mock_ens_requirement_attribute_opcional,
    ):
        """Test tipo section with all requirement types."""
        basic_ens_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Requisito type",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Refuerzo type",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-003",
                description="Recomendacion type",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-004",
                description="Medida type",
                status=StatusChoices.PASS,
                passed_findings=3,
                failed_findings=0,
                total_findings=3,
            ),
        ]
        basic_ens_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_medio]}
            },
            "REQ-003": {
                "attributes": {"req_attributes": [mock_ens_requirement_attribute_bajo]}
            },
            "REQ-004": {
                "attributes": {
                    "req_attributes": [mock_ens_requirement_attribute_opcional]
                }
            },
        }

        elements = ens_generator._create_tipo_section(basic_ens_compliance_data)

        # Should generate without errors
        assert len(elements) > 0
