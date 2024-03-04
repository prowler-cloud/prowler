import sys
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, ValidationError, root_validator

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


# Generic Compliance Requirement Attribute
class Generic_Compliance_Requirement_Attribute(BaseModel):
    """Generic Compliance Requirement Attribute"""

    ItemId: Optional[str]
    Section: Optional[str]
    SubSection: Optional[str]
    SubGroup: Optional[str]
    Service: Optional[str]
    Type: Optional[str]


class CIS_Requirement_Attribute_Profile(str):
    """CIS Requirement Attribute Profile"""

    Level_1 = "Level 1"
    Level_2 = "Level 2"


class CIS_Requirement_Attribute_AssessmentStatus(str):
    """CIS Requirement Attribute Assessment Status"""

    Manual = "Manual"
    Automated = "Automated"


# CIS Requirement Attribute
class CIS_Requirement_Attribute(BaseModel):
    """CIS Requirement Attribute"""

    Section: str
    Profile: CIS_Requirement_Attribute_Profile
    AssessmentStatus: CIS_Requirement_Attribute_AssessmentStatus
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
    SubSection: Optional[str]
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


# MITRE Requirement Attribute
class Mitre_Requirement_Attribute(BaseModel):
    """MITRE Requirement Attribute"""

    AWSService: str
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
    Attributes: list[Mitre_Requirement_Attribute]
    Checks: list[str]


# Base Compliance Model
# TODO: move this to compliance folder
class Compliance_Requirement(BaseModel):
    """Compliance_Requirement holds the base model for every requirement within a compliance framework"""

    Id: str
    Description: str
    Name: Optional[str]
    Attributes: list[
        Union[
            CIS_Requirement_Attribute,
            ENS_Requirement_Attribute,
            ISO27001_2013_Requirement_Attribute,
            AWS_Well_Architected_Requirement_Attribute,
            # Generic_Compliance_Requirement_Attribute must be the last one since it is the fallback for generic compliance framework
            Generic_Compliance_Requirement_Attribute,
        ]
    ]
    Checks: list[str]


class Compliance_Base_Model(BaseModel):
    """Compliance_Base_Model holds the base model for every compliance framework"""

    Framework: str
    Provider: str
    Version: Optional[str]
    Description: str
    Requirements: list[Union[Mitre_Requirement, Compliance_Requirement]]

    @root_validator(pre=True)
    # noqa: F841 - since vulture raises unused variable 'cls'
    def framework_and_provider_must_not_be_empty(cls, values):  # noqa: F841
        framework, provider = (
            values.get("Framework"),
            values.get("Provider"),
        )
        if framework == "" or provider == "":
            raise ValueError("Framework or Provider must not be empty")
        return values


# Testing Pending
def load_compliance_framework(
    compliance_specification_file: str,
) -> Compliance_Base_Model:
    """load_compliance_framework loads and parse a Compliance Framework Specification"""
    try:
        compliance_framework = Compliance_Base_Model.parse_file(
            compliance_specification_file
        )
    except ValidationError as error:
        logger.critical(
            f"Compliance Framework Specification from {compliance_specification_file} is not valid: {error}"
        )
        sys.exit(1)
    else:
        return compliance_framework
