import gc
import os
import resource as _resource_module
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from celery.utils.log import get_task_logger
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _calculate_requirements_data_from_statistics,
    _load_findings_for_requirement_checks,
)

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Provider, StatusChoices
from api.utils import initialize_prowler_provider
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput

from .components import (
    ColumnConfig,
    create_data_table,
    create_info_table,
    create_status_badge,
)
from .config import (
    COLOR_BG_BLUE,
    COLOR_BG_LIGHT_BLUE,
    COLOR_BLUE,
    COLOR_BORDER_GRAY,
    COLOR_GRAY,
    COLOR_LIGHT_BLUE,
    COLOR_LIGHTER_BLUE,
    COLOR_PROWLER_DARK_GREEN,
    FINDINGS_TABLE_CHUNK_SIZE,
    PADDING_LARGE,
    PADDING_SMALL,
    FrameworkConfig,
)

logger = get_task_logger(__name__)


@contextmanager
def _log_phase(phase: str, *, scan_id: str, framework: str):
    """Log start/end timing and RSS deltas around a report-building section.

    Emits structured key=value logs so Grafana/Datadog/CloudWatch queries
    can pivot by ``phase``, ``framework`` and ``scan_id`` to find the
    slow/heavy section on any given scan. ``getrusage`` returns KB on
    Linux and bytes on macOS; the values are still useful in relative
    terms even though units differ across platforms.
    """
    start = time.perf_counter()
    rss_before = _resource_module.getrusage(_resource_module.RUSAGE_SELF).ru_maxrss
    logger.info(
        "phase_start phase=%s scan_id=%s framework=%s rss_kb=%d",
        phase,
        scan_id,
        framework,
        rss_before,
    )
    try:
        yield
    except Exception:
        elapsed = time.perf_counter() - start
        logger.exception(
            "phase_failed phase=%s scan_id=%s framework=%s elapsed_s=%.2f",
            phase,
            scan_id,
            framework,
            elapsed,
        )
        raise
    else:
        elapsed = time.perf_counter() - start
        rss_after = _resource_module.getrusage(_resource_module.RUSAGE_SELF).ru_maxrss
        logger.info(
            "phase_end phase=%s scan_id=%s framework=%s elapsed_s=%.2f "
            "rss_kb=%d delta_rss_kb=%d",
            phase,
            scan_id,
            framework,
            elapsed,
            rss_after,
            rss_after - rss_before,
        )


# Register fonts (done once at module load)
_fonts_registered: bool = False


def _register_fonts() -> None:
    """Register custom fonts for PDF generation.

    Uses a module-level flag to ensure fonts are only registered once,
    avoiding duplicate registration errors from reportlab.
    """
    global _fonts_registered
    if _fonts_registered:
        return

    fonts_dir = os.path.join(os.path.dirname(__file__), "../../assets/fonts")

    pdfmetrics.registerFont(
        TTFont(
            "PlusJakartaSans",
            os.path.join(fonts_dir, "PlusJakartaSans-Regular.ttf"),
        )
    )

    pdfmetrics.registerFont(
        TTFont(
            "FiraCode",
            os.path.join(fonts_dir, "FiraCode-Regular.ttf"),
        )
    )

    _fonts_registered = True


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class RequirementData:
    """Data for a single compliance requirement.

    Attributes:
        id: Requirement identifier
        description: Requirement description
        status: Compliance status (PASS, FAIL, MANUAL)
        passed_findings: Number of passed findings
        failed_findings: Number of failed findings
        total_findings: Total number of findings
        checks: List of check IDs associated with this requirement
        attributes: Framework-specific requirement attributes
    """

    id: str
    description: str
    status: str
    passed_findings: int = 0
    failed_findings: int = 0
    total_findings: int = 0
    checks: list[str] = field(default_factory=list)
    attributes: Any = None


@dataclass
class ComplianceData:
    """Aggregated compliance data for report generation.

    This dataclass holds all the data needed to generate a compliance report,
    including compliance framework metadata, requirements, and findings.

    Attributes:
        tenant_id: Tenant identifier
        scan_id: Scan identifier
        provider_id: Provider identifier
        compliance_id: Compliance framework identifier
        framework: Framework name (e.g., "CIS", "ENS")
        name: Full compliance framework name
        version: Framework version
        description: Framework description
        requirements: List of RequirementData objects
        attributes_by_requirement_id: Mapping of requirement IDs to their attributes
        findings_by_check_id: Mapping of check IDs to their findings
        provider_obj: Provider model object
        prowler_provider: Initialized Prowler provider
    """

    tenant_id: str
    scan_id: str
    provider_id: str
    compliance_id: str
    framework: str
    name: str
    version: str
    description: str
    requirements: list[RequirementData] = field(default_factory=list)
    attributes_by_requirement_id: dict[str, dict] = field(default_factory=dict)
    findings_by_check_id: dict[str, list[FindingOutput]] = field(default_factory=dict)
    provider_obj: Provider | None = None
    prowler_provider: Any = None


def get_requirement_metadata(
    requirement_id: str,
    attributes_by_requirement_id: dict[str, dict],
) -> Any | None:
    """Get the first requirement metadata object from attributes.

    This helper function extracts the requirement metadata (req_attributes)
    from the attributes dictionary. It's a common pattern used across all
    report generators.

    Args:
        requirement_id: The requirement ID to look up.
        attributes_by_requirement_id: Mapping of requirement IDs to their attributes.

    Returns:
        The first requirement attribute object, or None if not found.

    Example:
        >>> meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
        >>> if meta:
        ...     section = getattr(meta, "Section", "Unknown")
    """
    req_attrs = attributes_by_requirement_id.get(requirement_id, {})
    meta_list = req_attrs.get("attributes", {}).get("req_attributes", [])
    if meta_list:
        return meta_list[0]
    return None


# =============================================================================
# PDF Styles Cache
# =============================================================================

_PDF_STYLES_CACHE: dict[str, ParagraphStyle] | None = None


def create_pdf_styles() -> dict[str, ParagraphStyle]:
    """Create and return PDF paragraph styles used throughout the report.

    Styles are cached on first call to improve performance.

    Returns:
        Dictionary containing the following styles:
            - 'title': Title style with prowler green color
            - 'h1': Heading 1 style with blue color and background
            - 'h2': Heading 2 style with light blue color
            - 'h3': Heading 3 style for sub-headings
            - 'normal': Normal text style with left indent
            - 'normal_center': Normal text style without indent
    """
    global _PDF_STYLES_CACHE

    if _PDF_STYLES_CACHE is not None:
        return _PDF_STYLES_CACHE

    _register_fonts()
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=COLOR_PROWLER_DARK_GREEN,
        spaceAfter=20,
        fontName="PlusJakartaSans",
        alignment=TA_CENTER,
    )

    h1 = ParagraphStyle(
        "CustomH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_BLUE,
        spaceBefore=20,
        spaceAfter=12,
        fontName="PlusJakartaSans",
        leftIndent=0,
        borderWidth=2,
        borderColor=COLOR_BLUE,
        borderPadding=PADDING_LARGE,
        backColor=COLOR_BG_BLUE,
    )

    h2 = ParagraphStyle(
        "CustomH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=COLOR_LIGHT_BLUE,
        spaceBefore=15,
        spaceAfter=8,
        fontName="PlusJakartaSans",
        leftIndent=10,
        borderWidth=1,
        borderColor=COLOR_BORDER_GRAY,
        borderPadding=5,
        backColor=COLOR_BG_LIGHT_BLUE,
    )

    h3 = ParagraphStyle(
        "CustomH3",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=COLOR_LIGHTER_BLUE,
        spaceBefore=10,
        spaceAfter=6,
        fontName="PlusJakartaSans",
        leftIndent=20,
    )

    normal = ParagraphStyle(
        "CustomNormal",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_GRAY,
        spaceBefore=PADDING_SMALL,
        spaceAfter=PADDING_SMALL,
        leftIndent=30,
        fontName="PlusJakartaSans",
    )

    normal_center = ParagraphStyle(
        "CustomNormalCenter",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_GRAY,
        fontName="PlusJakartaSans",
    )

    _PDF_STYLES_CACHE = {
        "title": title_style,
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "normal": normal,
        "normal_center": normal_center,
    }

    return _PDF_STYLES_CACHE


# =============================================================================
# Base Report Generator
# =============================================================================


class BaseComplianceReportGenerator(ABC):
    """Abstract base class for compliance PDF report generators.

    This class implements the Template Method pattern, providing a common
    structure for all compliance reports while allowing subclasses to
    customize specific sections.

    Subclasses must implement:
        - create_executive_summary()
        - create_charts_section()
        - create_requirements_index()

    Optionally, subclasses can override:
        - create_cover_page()
        - create_detailed_findings()
        - get_footer_text()
    """

    def __init__(self, config: FrameworkConfig):
        """Initialize the report generator.

        Args:
            config: Framework configuration
        """
        self.config = config
        self.styles = create_pdf_styles()

    # =========================================================================
    # Template Method
    # =========================================================================

    def generate(
        self,
        tenant_id: str,
        scan_id: str,
        compliance_id: str,
        output_path: str,
        provider_id: str,
        provider_obj: Provider | None = None,
        requirement_statistics: dict[str, dict[str, int]] | None = None,
        findings_cache: dict[str, list[FindingOutput]] | None = None,
        prowler_provider: Any | None = None,
        **kwargs,
    ) -> None:
        """Generate the PDF compliance report.

        This is the template method that orchestrates the report generation.
        It calls abstract methods that subclasses must implement.

        Args:
            tenant_id: Tenant identifier for RLS context
            scan_id: Scan identifier
            compliance_id: Compliance framework identifier
            output_path: Path where the PDF will be saved
            provider_id: Provider identifier
            provider_obj: Optional pre-fetched Provider object
            requirement_statistics: Optional pre-aggregated statistics
            findings_cache: Optional pre-loaded findings cache
            prowler_provider: Optional pre-initialized Prowler provider. When
                generating multiple reports for the same scan the master
                function initializes this once and passes it in to avoid
                re-running boto3/Azure-SDK setup per framework.
            **kwargs: Additional framework-specific arguments
        """
        framework = self.config.display_name
        logger.info(
            "report_generation_start framework=%s scan_id=%s compliance_id=%s",
            framework,
            scan_id,
            compliance_id,
        )

        try:
            # 1. Load compliance data
            with _log_phase(
                "load_compliance_data", scan_id=scan_id, framework=framework
            ):
                data = self._load_compliance_data(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    compliance_id=compliance_id,
                    provider_id=provider_id,
                    provider_obj=provider_obj,
                    requirement_statistics=requirement_statistics,
                    findings_cache=findings_cache,
                    prowler_provider=prowler_provider,
                )

            # 2. Create PDF document
            doc = self._create_document(output_path, data)

            # 3. Build report elements incrementally to manage memory
            # We collect garbage after heavy sections to prevent OOM on large reports
            elements = []

            # Cover page (lightweight)
            with _log_phase("cover_page", scan_id=scan_id, framework=framework):
                elements.extend(self.create_cover_page(data))
                elements.append(PageBreak())

            # Executive summary (framework-specific)
            with _log_phase("executive_summary", scan_id=scan_id, framework=framework):
                elements.extend(self.create_executive_summary(data))

            # Body sections (charts + requirements index)
            # Override _build_body_sections() in subclasses to change section order
            with _log_phase("body_sections", scan_id=scan_id, framework=framework):
                elements.extend(self._build_body_sections(data))

            # Detailed findings - heaviest section, loads findings on-demand
            with _log_phase("detailed_findings", scan_id=scan_id, framework=framework):
                elements.extend(self.create_detailed_findings(data, **kwargs))
                gc.collect()  # Free findings data after processing

            # 4. Build the PDF
            logger.info(
                "doc_build_about_to_run framework=%s scan_id=%s elements=%d",
                framework,
                scan_id,
                len(elements),
            )
            with _log_phase("doc_build", scan_id=scan_id, framework=framework):
                self._build_pdf(doc, elements, data)

            # Final cleanup
            del elements
            gc.collect()

            logger.info(
                "report_generation_end framework=%s scan_id=%s output_path=%s",
                framework,
                scan_id,
                output_path,
            )

        except Exception:
            # logger.exception captures the full traceback; the contextual
            # keys keep production search-by-scan-id viable.
            logger.exception(
                "report_generation_failed framework=%s scan_id=%s compliance_id=%s",
                framework,
                scan_id,
                compliance_id,
            )
            raise

    def _build_body_sections(self, data: ComplianceData) -> list:
        """Build the body sections between executive summary and detailed findings.

        Override in subclasses to change section order.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        # Charts section (framework-specific) - heavy on memory due to matplotlib
        elements.extend(self.create_charts_section(data))
        elements.append(PageBreak())
        gc.collect()  # Free matplotlib resources

        # Requirements index (framework-specific)
        elements.extend(self.create_requirements_index(data))
        elements.append(PageBreak())

        return elements

    # =========================================================================
    # Abstract Methods (must be implemented by subclasses)
    # =========================================================================

    @abstractmethod
    def create_executive_summary(self, data: ComplianceData) -> list:
        """Create the executive summary section.

        This section typically includes:
        - Overall compliance score/metrics
        - High-level statistics
        - Critical findings summary

        Args:
            data: Aggregated compliance data

        Returns:
            List of ReportLab elements
        """

    @abstractmethod
    def create_charts_section(self, data: ComplianceData) -> list:
        """Create the charts and visualizations section.

        This section typically includes:
        - Compliance score charts by section
        - Distribution charts
        - Trend visualizations

        Args:
            data: Aggregated compliance data

        Returns:
            List of ReportLab elements
        """

    @abstractmethod
    def create_requirements_index(self, data: ComplianceData) -> list:
        """Create the requirements index/table of contents.

        This section typically includes:
        - Hierarchical list of requirements
        - Status indicators
        - Section groupings

        Args:
            data: Aggregated compliance data

        Returns:
            List of ReportLab elements
        """

    # =========================================================================
    # Common Methods (can be overridden by subclasses)
    # =========================================================================

    def create_cover_page(self, data: ComplianceData) -> list:
        """Create the report cover page.

        Args:
            data: Aggregated compliance data

        Returns:
            List of ReportLab elements
        """
        elements = []

        # Prowler logo
        logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/prowler_logo.png"
        )
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=5 * inch, height=1 * inch)
            elements.append(logo)

        elements.append(Spacer(1, 0.5 * inch))

        # Title
        title_text = f"{self.config.display_name} Report"
        elements.append(Paragraph(title_text, self.styles["title"]))
        elements.append(Spacer(1, 0.5 * inch))

        # Compliance info table
        info_rows = self._build_info_rows(data, language=self.config.language)

        info_table = create_info_table(
            rows=info_rows,
            label_width=2 * inch,
            value_width=4 * inch,
            normal_style=self.styles["normal_center"],
        )
        elements.append(info_table)

        return elements

    def _build_info_rows(
        self, data: ComplianceData, language: str = "en"
    ) -> list[tuple[str, str]]:
        """Build the standard info rows for the cover page table.

        This helper method creates the common metadata rows used in all
        report cover pages. Subclasses can use this to maintain consistency
        while customizing other aspects of the cover page.

        Args:
            data: Aggregated compliance data.
            language: Language for labels ("en" or "es").

        Returns:
            List of (label, value) tuples for the info table.
        """
        # Labels based on language
        labels = {
            "en": {
                "framework": "Framework:",
                "id": "ID:",
                "name": "Name:",
                "version": "Version:",
                "provider": "Provider:",
                "account_id": "Account ID:",
                "alias": "Alias:",
                "scan_id": "Scan ID:",
                "description": "Description:",
            },
            "es": {
                "framework": "Framework:",
                "id": "ID:",
                "name": "Nombre:",
                "version": "Versión:",
                "provider": "Proveedor:",
                "account_id": "Account ID:",
                "alias": "Alias:",
                "scan_id": "Scan ID:",
                "description": "Descripción:",
            },
        }
        lang_labels = labels.get(language, labels["en"])

        info_rows = [
            (lang_labels["framework"], data.framework),
            (lang_labels["id"], data.compliance_id),
            (lang_labels["name"], data.name),
            (lang_labels["version"], data.version),
        ]

        # Add provider info if available
        if data.provider_obj:
            info_rows.append(
                (lang_labels["provider"], data.provider_obj.provider.upper())
            )
            info_rows.append(
                (lang_labels["account_id"], data.provider_obj.uid or "N/A")
            )
            info_rows.append((lang_labels["alias"], data.provider_obj.alias or "N/A"))

        info_rows.append((lang_labels["scan_id"], data.scan_id))

        if data.description:
            info_rows.append((lang_labels["description"], data.description))

        return info_rows

    def create_detailed_findings(self, data: ComplianceData, **kwargs) -> list:
        """Create the detailed findings section.

        This default implementation creates a requirement-by-requirement
        breakdown with findings tables. Subclasses can override for
        framework-specific presentation.

        This method implements on-demand loading of findings using the shared
        findings cache to minimize database queries and memory usage.

        Args:
            data: Aggregated compliance data
            **kwargs: Framework-specific options (e.g., only_failed)

        Returns:
            List of ReportLab elements
        """
        elements = []
        only_failed = kwargs.get("only_failed", True)
        include_manual = kwargs.get("include_manual", False)

        # Filter requirements if needed
        requirements = data.requirements
        if only_failed:
            # Include FAIL requirements, and optionally MANUAL if include_manual is True
            if include_manual:
                requirements = [
                    r
                    for r in requirements
                    if r.status in (StatusChoices.FAIL, StatusChoices.MANUAL)
                ]
            else:
                requirements = [
                    r for r in requirements if r.status == StatusChoices.FAIL
                ]

        # Collect all check IDs for requirements that will be displayed
        # This allows us to load only the findings we actually need (memory optimization)
        check_ids_to_load = []
        for req in requirements:
            check_ids_to_load.extend(req.checks)

        # Load findings on-demand only for the checks that will be displayed.
        # When ``only_failed`` is active at requirement level, also push the
        # FAIL filter down to the finding level: a requirement marked FAIL
        # because 1/1000 findings failed must not render a table dominated by
        # 999 PASS rows. That hides the actual failure under noise and
        # makes the per-check cap truncate the wrong rows.
        # ``total_counts`` is populated with the pre-cap total per check_id
        # (FAIL-only when only_failed is active) so the "Showing first N of
        # M" banner uses the same denominator the reader cares about.
        logger.info("Loading findings on-demand for %d requirements", len(requirements))
        total_counts: dict[str, int] = {}
        findings_by_check_id = _load_findings_for_requirement_checks(
            data.tenant_id,
            data.scan_id,
            check_ids_to_load,
            data.prowler_provider,
            data.findings_by_check_id,  # Pass the cache to update it
            total_counts_out=total_counts,
            only_failed_findings=only_failed,
        )

        for req in requirements:
            # Requirement header
            elements.append(
                Paragraph(
                    f"{req.id}: {req.description}",
                    self.styles["h1"],
                )
            )

            # Status badge
            elements.append(create_status_badge(req.status))
            elements.append(Spacer(1, 0.1 * inch))

            # Hook for subclasses to add extra detail (e.g., CSA attributes)
            elements.extend(self._render_requirement_detail_extras(req, data))

            # Findings for this requirement
            for check_id in req.checks:
                elements.append(Paragraph(f"Check: {check_id}", self.styles["h2"]))

                findings = findings_by_check_id.get(check_id, [])
                if not findings:
                    elements.append(
                        Paragraph(
                            "- No information for this finding currently",
                            self.styles["normal"],
                        )
                    )
                else:
                    # Surface truncation BEFORE the tables so readers see it
                    # at the same scroll position as the data itself, not
                    # after thousands of rendered rows.
                    loaded = len(findings)
                    total = total_counts.get(check_id, loaded)
                    if total > loaded:
                        kind = "failed findings" if only_failed else "findings"
                        elements.append(
                            Paragraph(
                                f"<b>&#9888; Showing first {loaded:,} of "
                                f"{total:,} {kind} for this check.</b> "
                                f"Use the CSV or JSON export for the full "
                                f"list. The PDF caps detail rows to keep "
                                f"the report readable and bounded in size.",
                                self.styles["normal"],
                            )
                        )
                        elements.append(Spacer(1, 0.05 * inch))

                    # Create chunked findings tables to prevent OOM when a
                    # single check has thousands of findings (ReportLab
                    # resolves layout per Flowable, so many small tables
                    # render contiguously with a bounded memory peak).
                    findings_tables = self._create_findings_tables(findings)
                    elements.extend(findings_tables)

                elements.append(Spacer(1, 0.1 * inch))

            elements.append(PageBreak())

        return elements

    def get_footer_text(self, page_num: int) -> tuple[str, str]:
        """Get footer text for a page.

        Args:
            page_num: Current page number

        Returns:
            Tuple of (left_text, right_text) for the footer
        """
        if self.config.language == "es":
            page_text = f"Página {page_num}"
        else:
            page_text = f"Page {page_num}"

        return page_text, "Powered by Prowler"

    def _render_requirement_detail_extras(
        self, req: RequirementData, data: ComplianceData
    ) -> list:
        """Hook for subclasses to render extra content in detailed findings.

        Called after the status badge for each requirement in the detailed
        findings section. Override in subclasses to add framework-specific
        metadata (e.g., CSA CCM attributes).

        Args:
            req: The requirement being rendered.
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements (empty by default).
        """
        return []

    # =========================================================================
    # Private Helper Methods
    # =========================================================================

    def _load_compliance_data(
        self,
        tenant_id: str,
        scan_id: str,
        compliance_id: str,
        provider_id: str,
        provider_obj: Provider | None,
        requirement_statistics: dict | None,
        findings_cache: dict | None,
        prowler_provider: Any | None = None,
    ) -> ComplianceData:
        """Load and aggregate compliance data from the database.

        Args:
            tenant_id: Tenant identifier
            scan_id: Scan identifier
            compliance_id: Compliance framework identifier
            provider_id: Provider identifier
            provider_obj: Optional pre-fetched Provider
            requirement_statistics: Optional pre-aggregated statistics
            findings_cache: Optional pre-loaded findings
            prowler_provider: Optional pre-initialized Prowler provider. When
                the master function initializes it once and passes it in,
                we skip the per-report ``initialize_prowler_provider`` call.

        Returns:
            Aggregated ComplianceData object
        """
        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
            # Load provider
            if provider_obj is None:
                provider_obj = Provider.objects.get(id=provider_id)

            if prowler_provider is None:
                prowler_provider = initialize_prowler_provider(provider_obj)
            provider_type = provider_obj.provider

            # Load compliance framework
            frameworks_bulk = Compliance.get_bulk(provider_type)
            compliance_obj = frameworks_bulk.get(compliance_id)

            if not compliance_obj:
                raise ValueError(f"Compliance framework not found: {compliance_id}")

            framework = getattr(compliance_obj, "Framework", "N/A")
            name = getattr(compliance_obj, "Name", "N/A")
            version = getattr(compliance_obj, "Version", "N/A")
            description = getattr(compliance_obj, "Description", "")

        # Aggregate requirement statistics
        if requirement_statistics is None:
            logger.info("Aggregating requirement statistics for scan %s", scan_id)
            requirement_statistics = _aggregate_requirement_statistics_from_database(
                tenant_id, scan_id
            )
        else:
            logger.info("Reusing pre-aggregated statistics for scan %s", scan_id)

        # Calculate requirements data
        attributes_by_requirement_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                compliance_obj, requirement_statistics
            )
        )

        # Convert to RequirementData objects
        requirements = []
        for req_dict in requirements_list:
            req = RequirementData(
                id=req_dict["id"],
                description=req_dict["attributes"].get("description", ""),
                status=req_dict["attributes"].get("status", StatusChoices.MANUAL),
                passed_findings=req_dict["attributes"].get("passed_findings", 0),
                failed_findings=req_dict["attributes"].get("failed_findings", 0),
                total_findings=req_dict["attributes"].get("total_findings", 0),
                checks=attributes_by_requirement_id.get(req_dict["id"], {})
                .get("attributes", {})
                .get("checks", []),
            )
            requirements.append(req)

        return ComplianceData(
            tenant_id=tenant_id,
            scan_id=scan_id,
            provider_id=provider_id,
            compliance_id=compliance_id,
            framework=framework,
            name=name,
            version=version,
            description=description,
            requirements=requirements,
            attributes_by_requirement_id=attributes_by_requirement_id,
            findings_by_check_id=findings_cache if findings_cache is not None else {},
            provider_obj=provider_obj,
            prowler_provider=prowler_provider,
        )

    def _create_document(
        self, output_path: str, data: ComplianceData
    ) -> SimpleDocTemplate:
        """Create the PDF document template.

        Validates that ``output_path`` is a filesystem path string with an
        existing parent directory. SimpleDocTemplate technically accepts a
        BytesIO too, but we want every report to land on disk so the
        Celery worker doesn't hold the full PDF in memory while uploading
        to S3.

        Args:
            output_path: Path for the output PDF
            data: Compliance data for metadata

        Returns:
            Configured SimpleDocTemplate

        Raises:
            TypeError: ``output_path`` is not a string.
            FileNotFoundError: The parent directory does not exist.
        """
        if not isinstance(output_path, str):
            raise TypeError(
                "output_path must be a filesystem path string; "
                f"got {type(output_path).__name__}"
            )
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.isdir(parent_dir):
            raise FileNotFoundError(f"Output directory does not exist: {parent_dir}")

        return SimpleDocTemplate(
            output_path,
            pagesize=letter,
            title=f"{self.config.display_name} Report - {data.framework}",
            author="Prowler",
            subject=f"Compliance Report for {data.framework}",
            creator="Prowler Engineering Team",
            keywords=f"compliance,{data.framework},security,framework,prowler",
        )

    def _build_pdf(
        self,
        doc: SimpleDocTemplate,
        elements: list,
        data: ComplianceData,
    ) -> None:
        """Build the final PDF with footers.

        Args:
            doc: Document template
            elements: List of ReportLab elements
            data: Compliance data
        """

        def add_footer(
            canvas_obj: canvas.Canvas,
            doc_template: SimpleDocTemplate,
        ) -> None:
            canvas_obj.saveState()
            width, _ = doc_template.pagesize
            left_text, right_text = self.get_footer_text(doc_template.page)

            canvas_obj.setFont("PlusJakartaSans", 9)
            canvas_obj.setFillColorRGB(0.4, 0.4, 0.4)
            canvas_obj.drawString(30, 20, left_text)

            text_width = canvas_obj.stringWidth(right_text, "PlusJakartaSans", 9)
            canvas_obj.drawString(width - text_width - 30, 20, right_text)
            canvas_obj.restoreState()

        doc.build(
            elements,
            onFirstPage=add_footer,
            onLaterPages=add_footer,
        )

    # Column layout shared by all findings sub-tables. Defined as a method so
    # subclasses can override it without re-implementing the chunking logic.
    def _findings_table_columns(self) -> list[ColumnConfig]:
        return [
            ColumnConfig("Finding", 2.5 * inch, "title"),
            ColumnConfig("Resource", 3 * inch, "resource_name"),
            ColumnConfig("Severity", 0.9 * inch, "severity"),
            ColumnConfig("Status", 0.9 * inch, "status"),
            ColumnConfig("Region", 0.9 * inch, "region"),
        ]

    @staticmethod
    def _finding_to_row(f: FindingOutput) -> dict[str, str]:
        """Project a FindingOutput onto the row dict the table expects.

        Kept defensive: missing metadata or attributes return empty strings
        rather than raising, so a single malformed finding never breaks the
        whole report.
        """
        metadata = getattr(f, "metadata", None)
        title = (
            getattr(metadata, "CheckTitle", getattr(f, "check_id", ""))
            if metadata
            else getattr(f, "check_id", "")
        )
        resource_name = getattr(f, "resource_name", "") or getattr(
            f, "resource_uid", ""
        )
        severity = getattr(metadata, "Severity", "").capitalize() if metadata else ""
        return {
            "title": title,
            "resource_name": resource_name,
            "severity": severity,
            "status": getattr(f, "status", "").upper(),
            "region": getattr(f, "region", "global"),
        }

    def _create_findings_tables(
        self,
        findings: list[FindingOutput],
        chunk_size: int | None = None,
    ) -> list[Any]:
        """Build a list of small findings tables to keep ``doc.build()`` memory bounded.

        ReportLab resolves layout (column widths, row heights, page-breaks)
        per Flowable. A single ``LongTable`` of 15k rows forces all of that
        to be computed at once and reliably OOMs the worker on large scans.
        Splitting into chunks of ``chunk_size`` rows produces an equivalent-
        looking PDF (LongTable repeats headers; chunks render contiguously)
        with a bounded memory peak per chunk.

        Args:
            findings: List of finding objects for a single check.
            chunk_size: Rows per sub-table. ``None`` uses
                ``FINDINGS_TABLE_CHUNK_SIZE`` from config.

        Returns:
            List of ReportLab flowables (interleaved ``Table``/``LongTable``
            and small ``Spacer`` between chunks). Empty list when there are
            no findings.
        """
        if not findings:
            return []

        chunk_size = chunk_size or FINDINGS_TABLE_CHUNK_SIZE

        # Build all rows first so we can chunk without re-walking the
        # FindingOutput list. Malformed findings are skipped with a logged
        # exception, never enough to abort the entire report.
        rows: list[dict[str, str]] = []
        for f in findings:
            try:
                rows.append(self._finding_to_row(f))
            except Exception:
                logger.exception(
                    "Skipping malformed finding while building table for check %s",
                    getattr(f, "check_id", "unknown"),
                )

        if not rows:
            return []

        columns = self._findings_table_columns()

        flowables: list = []
        total = len(rows)
        for start in range(0, total, chunk_size):
            chunk = rows[start : start + chunk_size]
            flowables.append(
                create_data_table(
                    data=chunk,
                    columns=columns,
                    header_color=self.config.primary_color,
                    normal_style=self.styles["normal_center"],
                )
            )
            # A tiny spacer between chunks keeps them visually contiguous
            # without forcing a page-break (KeepTogether would negate the
            # memory benefit of chunking).
            if start + chunk_size < total:
                flowables.append(Spacer(1, 0.05 * inch))

        if total > chunk_size:
            logger.debug(
                "Built %d findings sub-tables (chunk_size=%d, total_findings=%d)",
                (total + chunk_size - 1) // chunk_size,
                chunk_size,
                total,
            )

        return flowables

    def _create_findings_table(self, findings: list[FindingOutput]) -> Any:
        """Deprecated alias kept for backwards compatibility.

        Returns the first chunk produced by ``_create_findings_tables``.
        New callers MUST use ``_create_findings_tables``, which returns a
        list of flowables and is what ``create_detailed_findings`` invokes.
        """
        flowables = self._create_findings_tables(findings)
        if flowables:
            return flowables[0]
        # Empty input → return an empty (header-only) table so callers that
        # used to receive a Table never get None.
        return create_data_table(
            data=[],
            columns=self._findings_table_columns(),
            header_color=self.config.primary_color,
            normal_style=self.styles["normal_center"],
        )
