import json
import os
import sys
from enum import Enum
from typing import Optional, Union

from pydantic.v1 import BaseModel, Field, ValidationError, root_validator

from prowler.lib.check.utils import list_compliance_modules
from prowler.lib.logger import logger


# ENS - Esquema Nacional de Seguridad - España
class ENS_Requirement_Attribute_Nivel(str, Enum):
    """ENS V3 Requirement Attribute Level"""

    opcional = "opcional"
    bajo = "bajo"
    medio = "medio"
    alto = "alto"


class ENS_Requirement_Attribute_Dimensiones(str, Enum):
    """ENS V3 Requirement Attribute Dimensions"""

    confidencialidad = "confidencialidad"
    integridad = "integridad"
    trazabilidad = "trazabilidad"
    autenticidad = "autenticidad"
    disponibilidad = "disponibilidad"


class ENS_Requirement_Attribute_Tipos(str, Enum):
    """ENS Requirement Attribute  Tipos"""

    refuerzo = "refuerzo"
    requisito = "requisito"
    recomendacion = "recomendacion"
    medida = "medida"


class ENS_Requirement_Attribute(BaseModel):
    """ENS V3 Framework Requirement Attribute"""

    IdGrupoControl: str
    Marco: str
    Categoria: str
    DescripcionControl: str
    Tipo: ENS_Requirement_Attribute_Tipos
    Nivel: ENS_Requirement_Attribute_Nivel
    Dimensiones: list[ENS_Requirement_Attribute_Dimensiones]
    ModoEjecucion: str
    Dependencias: list[str]


# Generic Compliance Requirement Attribute
class Generic_Compliance_Requirement_Attribute(BaseModel):
    """Generic Compliance Requirement Attribute"""

    ItemId: Optional[str] = None
    Section: Optional[str] = None
    SubSection: Optional[str] = None
    SubGroup: Optional[str] = None
    Service: Optional[str] = None
    Type: Optional[str] = None
    Comment: Optional[str] = None


class CIS_Requirement_Attribute_Profile(str, Enum):
    """CIS Requirement Attribute Profile"""

    Level_1 = "Level 1"
    Level_2 = "Level 2"
    E3_Level_1 = "E3 Level 1"
    E3_Level_2 = "E3 Level 2"
    E5_Level_1 = "E5 Level 1"
    E5_Level_2 = "E5 Level 2"


class CIS_Requirement_Attribute_AssessmentStatus(str, Enum):
    """CIS Requirement Attribute Assessment Status"""

    Manual = "Manual"
    Automated = "Automated"


# CIS Requirement Attribute
class CIS_Requirement_Attribute(BaseModel):
    """CIS Requirement Attribute"""

    Section: str
    SubSection: Optional[str] = None
    Profile: CIS_Requirement_Attribute_Profile
    AssessmentStatus: CIS_Requirement_Attribute_AssessmentStatus
    Description: str
    RationaleStatement: str
    ImpactStatement: str
    RemediationProcedure: str
    AuditProcedure: str
    AdditionalInformation: str
    DefaultValue: Optional[str] = None
    References: str


class EssentialEight_Requirement_Attribute_MaturityLevel(str, Enum):
    """ASD Essential Eight Maturity Level"""

    ML1 = "ML1"
    ML2 = "ML2"
    ML3 = "ML3"


class EssentialEight_Requirement_Attribute_AssessmentStatus(str, Enum):
    """Essential Eight Requirement Attribute Assessment Status"""

    Manual = "Manual"
    Automated = "Automated"


class EssentialEight_Requirement_Attribute_CloudApplicability(str, Enum):
    """How well the ASD control maps to AWS cloud infrastructure."""

    Full = "full"
    Partial = "partial"
    Limited = "limited"
    NonApplicable = "non-applicable"


# Essential Eight Requirement Attribute
class EssentialEight_Requirement_Attribute(BaseModel):
    """ASD Essential Eight Requirement Attribute"""

    Section: str
    MaturityLevel: EssentialEight_Requirement_Attribute_MaturityLevel
    AssessmentStatus: EssentialEight_Requirement_Attribute_AssessmentStatus
    CloudApplicability: EssentialEight_Requirement_Attribute_CloudApplicability
    MitigatedThreats: list[str]
    Description: str
    RationaleStatement: str
    ImpactStatement: str
    RemediationProcedure: str
    AuditProcedure: str
    AdditionalInformation: str
    References: str


# Well Architected Requirement Attribute
class AWS_Well_Architected_Requirement_Attribute(BaseModel):
    """AWS Well Architected Requirement Attribute"""

    Name: str
    WellArchitectedQuestionId: str
    WellArchitectedPracticeId: str
    Section: str
    SubSection: Optional[str] = None
    LevelOfRisk: str
    AssessmentMethod: str
    Description: str
    ImplementationGuidanceUrl: str


# ISO27001 Requirement Attribute
class ISO27001_2013_Requirement_Attribute(BaseModel):
    """ISO27001 Requirement Attribute"""

    Category: str
    Objetive_ID: str
    Objetive_Name: str
    Check_Summary: str


# MITRE Requirement Attribute for AWS
class Mitre_Requirement_Attribute_AWS(BaseModel):
    """MITRE Requirement Attribute"""

    AWSService: str
    Category: str
    Value: str
    Comment: str


# MITRE Requirement Attribute for Azure
class Mitre_Requirement_Attribute_Azure(BaseModel):
    """MITRE Requirement Attribute"""

    AzureService: str
    Category: str
    Value: str
    Comment: str


# MITRE Requirement Attribute for GCP
class Mitre_Requirement_Attribute_GCP(BaseModel):
    """MITRE Requirement Attribute"""

    GCPService: str
    Category: str
    Value: str
    Comment: str


# MITRE Requirement
class Mitre_Requirement(BaseModel):
    """Mitre_Requirement holds the model for every MITRE requirement"""

    Name: str
    Id: str
    Tactics: list[str]
    SubTechniques: list[str]
    Description: str
    Platforms: list[str]
    TechniqueURL: str
    Attributes: Union[
        list[Mitre_Requirement_Attribute_AWS],
        list[Mitre_Requirement_Attribute_Azure],
        list[Mitre_Requirement_Attribute_GCP],
    ]
    Checks: list[str]


# KISA-ISMS-P Requirement Attribute
class KISA_ISMSP_Requirement_Attribute(BaseModel):
    """KISA ISMS-P Requirement Attribute"""

    Domain: str
    Subdomain: str
    Section: str
    AuditChecklist: Optional[list[str]] = None
    RelatedRegulations: Optional[list[str]] = None
    AuditEvidence: Optional[list[str]] = None
    NonComplianceCases: Optional[list[str]] = None


# Prowler ThreatScore Requirement Attribute
class Prowler_ThreatScore_Requirement_Attribute(BaseModel):
    """Prowler ThreatScore Requirement Attribute"""

    Title: str
    Section: str
    SubSection: str
    AttributeDescription: str
    AdditionalInformation: str
    LevelOfRisk: int
    Weight: int


# CCC Requirement Attribute
class CCC_Requirement_Attribute(BaseModel):
    """CCC Requirement Attribute"""

    FamilyName: str
    FamilyDescription: str
    Section: str
    SubSection: str
    SubSectionObjective: str
    Applicability: list[str]
    Recommendation: str
    SectionThreatMappings: list[dict]
    SectionGuidelineMappings: list[dict]


# C5 Germany Requirement Attribute
class C5Germany_Requirement_Attribute(BaseModel):
    """C5 Germany Requirement Attribute"""

    Section: str
    SubSection: str
    Type: str
    AboutCriteria: str
    ComplementaryCriteria: str


# CSA CCM v4 Requirement Attribute
class CSA_CCM_Requirement_Attribute(BaseModel):
    """CSA Cloud Controls Matrix (CCM) v4 Requirement Attribute"""

    Section: str
    CCMLite: str
    IaaS: str
    PaaS: str
    SaaS: str
    ScopeApplicability: list[dict]


# Base Compliance Model
# TODO: move this to compliance folder
class Compliance_Requirement(BaseModel):
    """Compliance_Requirement holds the base model for every requirement within a compliance framework"""

    Id: str
    Description: str
    Name: Optional[str] = None
    Attributes: list[
        Union[
            EssentialEight_Requirement_Attribute,
            CIS_Requirement_Attribute,
            ENS_Requirement_Attribute,
            ISO27001_2013_Requirement_Attribute,
            AWS_Well_Architected_Requirement_Attribute,
            KISA_ISMSP_Requirement_Attribute,
            Prowler_ThreatScore_Requirement_Attribute,
            CCC_Requirement_Attribute,
            C5Germany_Requirement_Attribute,
            CSA_CCM_Requirement_Attribute,
            # Generic_Compliance_Requirement_Attribute must be the last one since it is the fallback for generic compliance framework
            Generic_Compliance_Requirement_Attribute,
        ]
    ]
    Checks: list[str]


class Compliance(BaseModel):
    """Compliance holds the base model for every compliance framework"""

    Framework: str
    Name: str
    Provider: str
    Version: Optional[str] = None
    Description: str
    Requirements: list[
        Union[
            Mitre_Requirement,
            Compliance_Requirement,
        ]
    ]

    @root_validator(pre=True)
    # noqa: F841 - since vulture raises unused variable 'cls'
    def framework_and_provider_must_not_be_empty(cls, values):  # noqa: F841
        framework, provider, name = (
            values.get("Framework"),
            values.get("Provider"),
            values.get("Name"),
        )
        if framework == "" or provider == "" or name == "":
            raise ValueError("Framework, Provider or Name must not be empty")
        return values

    @staticmethod
    def list(bulk_compliance_frameworks: dict, provider: str = None) -> list[str]:
        """
        Returns a list of compliance frameworks from bulk compliance frameworks

        Args:
            bulk_compliance_frameworks (dict): The bulk compliance frameworks
            provider (str): The provider name

        Returns:
            list: The list of compliance frameworks
        """
        if provider:
            compliance_frameworks = [
                compliance_framework
                for compliance_framework in bulk_compliance_frameworks.keys()
                if provider in compliance_framework
            ]
        else:
            compliance_frameworks = [
                compliance_framework
                for compliance_framework in bulk_compliance_frameworks.keys()
            ]

        return compliance_frameworks

    @staticmethod
    def get(
        bulk_compliance_frameworks: dict, compliance_framework_name: str
    ) -> "Compliance":
        """
        Returns a compliance framework from bulk compliance frameworks

        Args:
            bulk_compliance_frameworks (dict): The bulk compliance frameworks
            compliance_framework_name (str): The compliance framework name

        Returns:
            Compliance: The compliance framework
        """
        return bulk_compliance_frameworks.get(compliance_framework_name, None)

    @staticmethod
    def list_requirements(
        bulk_compliance_frameworks: dict, compliance_framework: str = None
    ) -> list:
        """
        Returns a list of compliance requirements from a compliance framework

        Args:
            bulk_compliance_frameworks (dict): The bulk compliance frameworks
            compliance_framework (str): The compliance framework name

        Returns:
            list: The list of compliance requirements for the provided compliance framework
        """
        compliance_requirements = []

        if bulk_compliance_frameworks and compliance_framework:
            compliance_requirements = [
                compliance_requirement.Id
                for compliance_requirement in bulk_compliance_frameworks.get(
                    compliance_framework
                ).Requirements
            ]

        return compliance_requirements

    @staticmethod
    def get_requirement(
        bulk_compliance_frameworks: dict, compliance_framework: str, requirement_id: str
    ) -> Union[Mitre_Requirement, Compliance_Requirement]:
        """
        Returns a compliance requirement from a compliance framework

        Args:
            bulk_compliance_frameworks (dict): The bulk compliance frameworks
            compliance_framework (str): The compliance framework name
            requirement_id (str): The compliance requirement ID

        Returns:
            Mitre_Requirement | Compliance_Requirement: The compliance requirement
        """
        requirement = None
        for compliance_requirement in bulk_compliance_frameworks.get(
            compliance_framework
        ).Requirements:
            if compliance_requirement.Id == requirement_id:
                requirement = compliance_requirement
                break

        return requirement

    @staticmethod
    def get_bulk(provider: str) -> dict:
        """Bulk load all compliance frameworks specification into a dict"""
        try:
            bulk_compliance_frameworks = {}
            available_compliance_framework_modules = list_compliance_modules()
            for compliance_framework in available_compliance_framework_modules:
                if provider in compliance_framework.name:
                    compliance_specification_dir_path = (
                        f"{compliance_framework.module_finder.path}/{provider}"
                    )
                    # for compliance_framework in available_compliance_framework_modules:
                    for filename in os.listdir(compliance_specification_dir_path):
                        file_path = os.path.join(
                            compliance_specification_dir_path, filename
                        )
                        # Check if it is a file and ti size is greater than 0
                        if os.path.isfile(file_path) and os.stat(file_path).st_size > 0:
                            # Open Compliance file in JSON
                            # cis_v1.4_aws.json --> cis_v1.4_aws
                            compliance_framework_name = filename.split(".json")[0]
                            # Store the compliance info
                            bulk_compliance_frameworks[compliance_framework_name] = (
                                load_compliance_framework(file_path)
                            )
        except Exception as e:
            logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")

        return bulk_compliance_frameworks


# Testing Pending
def load_compliance_framework(
    compliance_specification_file: str,
) -> Compliance:
    """load_compliance_framework loads and parse a Compliance Framework Specification"""
    try:
        compliance_framework = Compliance.parse_file(compliance_specification_file)
    except ValidationError as error:
        logger.critical(
            f"Compliance Framework Specification from {compliance_specification_file} is not valid: {error}"
        )
        sys.exit(1)
    else:
        return compliance_framework


# ─── Universal Compliance Schema Models (Phase 1-3) ─────────────────────────


class OutputFormats(BaseModel):
    """Flags indicating in which output formats an attribute should be included."""

    csv: bool = True
    ocsf: bool = True


class AttributeMetadata(BaseModel):
    """Schema descriptor for a single attribute field in a universal compliance framework."""

    key: str
    label: Optional[str] = None
    type: str = "str"  # str, int, float, list_str, list_dict, bool
    enum: Optional[list] = None
    required: bool = False
    enum_display: Optional[dict] = None  # enum_value -> EnumValueDisplay dict
    enum_order: Optional[list] = None  # explicit ordering of enum values
    chart_label: Optional[str] = None  # axis label when used in charts
    output_formats: OutputFormats = Field(default_factory=OutputFormats)


class SplitByConfig(BaseModel):
    """Column-splitting configuration (e.g. CIS Level 1/Level 2)."""

    field: str
    values: list


class ScoringConfig(BaseModel):
    """Weighted scoring configuration (e.g. ThreatScore)."""

    risk_field: str
    weight_field: str


class TableLabels(BaseModel):
    """Custom pass/fail labels for console table rendering."""

    pass_label: str = "PASS"
    fail_label: str = "FAIL"
    provider_header: str = "Provider"
    group_header: Optional[str] = None
    status_header: str = "Status"
    title: Optional[str] = None
    results_title: Optional[str] = None
    footer_note: Optional[str] = None


class TableConfig(BaseModel):
    """Declarative rendering instructions for the console compliance table."""

    group_by: str
    split_by: Optional[SplitByConfig] = None
    scoring: Optional[ScoringConfig] = None
    labels: Optional[TableLabels] = None


class EnumValueDisplay(BaseModel):
    """Per-enum-value visual metadata for PDF rendering.

    Replaces hardcoded DIMENSION_MAPPING, TIPO_ICONS, nivel colors.
    """

    label: Optional[str] = None  # "Trazabilidad"
    abbreviation: Optional[str] = None  # "T"
    color: Optional[str] = None  # "#4286F4"
    icon: Optional[str] = None  # emoji


class ChartConfig(BaseModel):
    """Declarative chart description for PDF reports."""

    id: str
    type: str  # vertical_bar | horizontal_bar | radar
    group_by: str  # attribute key to group by
    title: Optional[str] = None
    x_label: Optional[str] = None
    y_label: Optional[str] = None
    value_source: str = "compliance_percent"
    color_mode: str = "by_value"  # by_value | fixed | by_group
    fixed_color: Optional[str] = None


class ScoringFormula(BaseModel):
    """Weighted scoring formula (e.g. ThreatScore)."""

    risk_field: str  # "LevelOfRisk"
    weight_field: str  # "Weight"
    risk_boost_factor: float = 0.25  # rfac = 1 + factor * risk_level


class CriticalRequirementsFilter(BaseModel):
    """Filter for critical requirements section in PDF reports."""

    filter_field: str  # "LevelOfRisk"
    min_value: Optional[int] = None  # 4 (int-based filter)
    filter_value: Optional[str] = None  # "alto" (string-based filter)
    status_filter: str = "FAIL"
    title: Optional[str] = None  # "Critical Failed Requirements"


class ReportFilter(BaseModel):
    """Default report filtering for PDF generation."""

    only_failed: bool = True
    include_manual: bool = False


class I18nLabels(BaseModel):
    """Localized labels for PDF report rendering."""

    report_title: Optional[str] = None
    page_label: str = "Page"
    powered_by: str = "Powered by Prowler"
    framework_label: str = "Framework:"
    version_label: str = "Version:"
    provider_label: str = "Provider:"
    description_label: str = "Description:"
    compliance_score_label: str = "Compliance Score by Sections"
    requirements_index_label: str = "Requirements Index"
    detailed_findings_label: str = "Detailed Findings"


class PDFConfig(BaseModel):
    """Declarative PDF report configuration.

    Drives the API report generator from JSON data instead of hardcoded
    Python config. Colors are hex strings (e.g. '#336699').
    """

    language: str = "en"
    logo_filename: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    bg_color: Optional[str] = None
    sections: Optional[list] = None
    section_short_names: Optional[dict] = None
    group_by_field: Optional[str] = None
    sub_group_by_field: Optional[str] = None
    section_titles: Optional[dict] = None
    charts: Optional[list] = None
    scoring: Optional[ScoringFormula] = None
    critical_filter: Optional[CriticalRequirementsFilter] = None
    filter: Optional[ReportFilter] = None
    labels: Optional[I18nLabels] = None


class UniversalComplianceRequirement(BaseModel):
    """Universal requirement with flat dict-based attributes."""

    id: str
    description: str
    name: Optional[str] = None
    attributes: dict = Field(default_factory=dict)
    checks: dict[str, list[str]] = Field(default_factory=dict)
    tactics: Optional[list] = None
    sub_techniques: Optional[list] = None
    platforms: Optional[list] = None
    technique_url: Optional[str] = None


class OutputsConfig(BaseModel):
    """Container for output-related configuration (table, PDF, etc.)."""

    table_config: Optional[TableConfig] = None
    pdf_config: Optional[PDFConfig] = None


class ComplianceFramework(BaseModel):
    """Universal top-level container for any compliance framework.

    Provider may be explicit (single-provider JSON) or derived from checks
    keys across all requirements.
    """

    framework: str
    name: str
    provider: Optional[str] = None
    version: Optional[str] = None
    description: str
    icon: Optional[str] = None
    requirements: list[UniversalComplianceRequirement]
    attributes_metadata: Optional[list[AttributeMetadata]] = None
    outputs: Optional[OutputsConfig] = None

    @root_validator
    # noqa: F841 - since vulture raises unused variable 'cls'
    def validate_attributes_against_metadata(cls, values):  # noqa: F841
        """Validate every Requirement's attributes dict against attributes_metadata.

        Checks:
        - Required keys (required=True) must be present in each Requirement.
        - Enum-constrained keys must have a value within the declared enum list.
        - Basic type validation (int, float, bool) for non-None values.
        """
        metadata = values.get("attributes_metadata")
        requirements = values.get("requirements", [])
        if not metadata:
            return values

        required_keys = {m.key for m in metadata if m.required}
        valid_keys = {m.key for m in metadata}
        enum_map = {m.key: m.enum for m in metadata if m.enum}
        type_map = {m.key: m.type for m in metadata}

        type_checks = {
            "int": int,
            "float": (int, float),
            "bool": bool,
        }

        errors = []
        for req in requirements:
            attrs = req.attributes

            # Required keys
            for key in required_keys:
                if key not in attrs or attrs[key] is None:
                    errors.append(
                        f"Requirement '{req.id}': missing required attribute '{key}'"
                    )

            # Unknown keys — anything outside the declared schema is a typo or drift
            unknown_keys = set(attrs) - valid_keys
            for key in sorted(unknown_keys):
                errors.append(
                    f"Requirement '{req.id}': unknown attribute '{key}' "
                    f"(not declared in attributes_metadata)"
                )

            # Enum validation
            for key, allowed in enum_map.items():
                if key in attrs and attrs[key] is not None:
                    if attrs[key] not in allowed:
                        errors.append(
                            f"Requirement '{req.id}': attribute '{key}' value "
                            f"'{attrs[key]}' not in {allowed}"
                        )

            # Type validation for non-string types
            for key in attrs:
                if key not in valid_keys or attrs[key] is None:
                    continue
                expected_type = type_map.get(key, "str")
                py_type = type_checks.get(expected_type)
                if py_type and not isinstance(attrs[key], py_type):
                    errors.append(
                        f"Requirement '{req.id}': attribute '{key}' expected "
                        f"type {expected_type}, got {type(attrs[key]).__name__}"
                    )

        if errors:
            detail = "\n  ".join(errors)
            raise ValueError(f"attributes_metadata validation failed:\n  {detail}")

        return values

    def get_providers(self) -> list:
        """Derive the set of providers this framework supports.

        Inspects checks keys across all requirements. Falls back to the
        explicit provider field for single-provider frameworks with no
        requirement-level checks.
        """
        providers = set()
        for req in self.requirements:
            providers.update(k.lower() for k in req.checks.keys())
        if self.provider and not providers:
            providers.add(self.provider.lower())
        return sorted(providers)

    def supports_provider(self, provider: str) -> bool:
        """Return True if this framework has checks for the given provider."""
        provider_lower = provider.lower()
        for req in self.requirements:
            if any(k.lower() == provider_lower for k in req.checks.keys()):
                return True
        return self.provider is not None and self.provider.lower() == provider_lower


# ─── Legacy-to-Universal Adapter (Phase 2) ──────────────────────────────────


def _infer_attribute_metadata(legacy: Compliance) -> Optional[list[AttributeMetadata]]:
    """Introspect the first requirement's attribute model to build attributes_metadata."""
    try:
        if not legacy.Requirements:
            return None

        first_req = legacy.Requirements[0]

        # MITRE requirements have Tactics at top level, not in Attributes
        if isinstance(first_req, Mitre_Requirement):
            return None

        if not first_req.Attributes:
            return None

        sample_attr = first_req.Attributes[0]
        metadata = []

        for field_name, field_obj in sample_attr.__fields__.items():
            field_type = field_obj.outer_type_
            type_str = "str"
            enum_values = None

            origin = getattr(field_type, "__origin__", None)
            if field_type is int:
                type_str = "int"
            elif field_type is float:
                type_str = "float"
            elif field_type is bool:
                type_str = "bool"
            elif origin is list:
                args = getattr(field_type, "__args__", ())
                if args and args[0] is dict:
                    type_str = "list_dict"
                else:
                    type_str = "list_str"
            elif isinstance(field_type, type) and issubclass(field_type, Enum):
                type_str = "str"
                enum_values = [e.value for e in field_type]

            metadata.append(
                AttributeMetadata(
                    key=field_name,
                    type=type_str,
                    enum=enum_values,
                    required=field_obj.required,
                )
            )

        return metadata
    except Exception:
        return None


def adapt_legacy_to_universal(legacy: Compliance) -> ComplianceFramework:
    """Convert a legacy Compliance object to a ComplianceFramework."""
    universal_requirements = []
    legacy_provider_key = legacy.Provider.lower()

    for req in legacy.Requirements:
        req_checks = {legacy_provider_key: list(req.Checks)} if req.Checks else {}
        if isinstance(req, Mitre_Requirement):
            # For MITRE, promote special fields and store raw attributes
            raw_attrs = [attr.dict() for attr in req.Attributes]
            attrs = {"_raw_attributes": raw_attrs}
            universal_requirements.append(
                UniversalComplianceRequirement(
                    id=req.Id,
                    description=req.Description,
                    name=req.Name,
                    attributes=attrs,
                    checks=req_checks,
                    tactics=req.Tactics,
                    sub_techniques=req.SubTechniques,
                    platforms=req.Platforms,
                    technique_url=req.TechniqueURL,
                )
            )
        else:
            # Standard requirement: flatten first attribute to dict
            if req.Attributes:
                attrs = req.Attributes[0].dict()
            else:
                attrs = {}
            universal_requirements.append(
                UniversalComplianceRequirement(
                    id=req.Id,
                    description=req.Description,
                    name=req.Name,
                    attributes=attrs,
                    checks=req_checks,
                )
            )

    inferred_metadata = _infer_attribute_metadata(legacy)

    return ComplianceFramework(
        framework=legacy.Framework,
        name=legacy.Name,
        provider=legacy.Provider,
        version=legacy.Version,
        description=legacy.Description,
        requirements=universal_requirements,
        attributes_metadata=inferred_metadata,
    )


def load_compliance_framework_universal(path: str) -> ComplianceFramework:
    """Load a compliance JSON as a ComplianceFramework, handling both new and legacy formats."""
    try:
        with open(path, "r") as f:
            data = json.load(f)

        if "attributes_metadata" in data or "requirements" in data:
            # New universal format — parse directly
            return ComplianceFramework(**data)
        else:
            # Legacy format — parse as Compliance, then adapt
            legacy = Compliance(**data)
            return adapt_legacy_to_universal(legacy)
    except Exception as e:
        logger.error(
            f"Failed to load universal compliance framework from {path}: "
            f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}"
        )
        return None


def _load_jsons_from_dir(dir_path: str, provider: str, bulk: dict) -> None:
    """Scan *dir_path* for JSON files and add matching frameworks to *bulk*."""
    for filename in os.listdir(dir_path):
        file_path = os.path.join(dir_path, filename)
        if not (
            os.path.isfile(file_path)
            and filename.endswith(".json")
            and os.stat(file_path).st_size > 0
        ):
            continue
        framework_name = filename.split(".json")[0]
        if framework_name in bulk:
            continue
        fw = load_compliance_framework_universal(file_path)
        if fw is None:
            continue
        if fw.provider and fw.provider.lower() == provider.lower():
            bulk[framework_name] = fw
        elif fw.supports_provider(provider):
            bulk[framework_name] = fw


def get_bulk_compliance_frameworks_universal(provider: str) -> dict:
    """Bulk load all compliance frameworks relevant to the given provider.

    Scans:

    1. The **top-level** ``prowler/compliance/`` directory for multi-provider
       JSONs (``Checks`` keyed by provider, no ``Provider`` field).
    2. Every **provider sub-directory** (``prowler/compliance/{p}/``) so that
       single-provider JSONs are also picked up.

    A framework is included when its explicit ``Provider`` matches
    (case-insensitive) **or** any requirement has dict-style ``Checks``
    with a key for *provider*.
    """
    bulk = {}
    try:
        available_modules = list_compliance_modules()

        # Resolve the compliance root once (parent of provider sub-dirs).
        compliance_root = None
        seen_paths = set()

        for module in available_modules:
            dir_path = f"{module.module_finder.path}/{module.name.split('.')[-1]}"
            if not os.path.isdir(dir_path) or dir_path in seen_paths:
                continue
            seen_paths.add(dir_path)

            # Remember the root the first time we see a valid sub-dir.
            if compliance_root is None:
                compliance_root = module.module_finder.path

            _load_jsons_from_dir(dir_path, provider, bulk)

        # Also scan top-level compliance/ for provider-agnostic JSONs.
        if compliance_root and os.path.isdir(compliance_root):
            _load_jsons_from_dir(compliance_root, provider, bulk)

    except Exception as e:
        logger.error(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")
    return bulk
