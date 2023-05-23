import sys
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, ValidationError, root_validator

from prowler.lib.logger import logger


# ENS - Esquema Nacional de Seguridad - España
class ENS_Requirements_Nivel(str, Enum):
    """ENS V3 Requirements Level"""

    opcional = "opcional"
    bajo = "bajo"
    medio = "medio"
    alto = "alto"


class ENS_Requirements_Dimensiones(str, Enum):
    """ENS V3 Requirements Dimensions"""

    confidencialidad = "confidencialidad"
    integridad = "integridad"
    trazabilidad = "trazabilidad"
    autenticidad = "autenticidad"
    disponibilidad = "disponibilidad"


class ENS_Requirements_Tipos(str, Enum):
    """ENS Requirements  Tipos"""

    refuerzo = "refuerzo"
    requisito = "requisito"
    recomendacion = "recomendacion"
    medida = "medida"


class ENS_Requirements(BaseModel):
    """ENS V3 Framework Requirements"""

    IdGrupoControl: str
    Marco: str
    Categoria: str
    DescripcionControl: str
    Tipo: ENS_Requirements_Tipos
    Nivel: ENS_Requirements_Nivel
    Dimensiones: list[ENS_Requirements_Dimensiones]


# Generic Compliance Requirements
class Generic_Compliance_Requirements(BaseModel):
    """Generic Compliance Requirements"""

    ItemId: str
    Section: Optional[str]
    SubSection: Optional[str]
    SubGroup: Optional[str]
    Service: str
    Soc_Type: Optional[str]


class CIS_Requirements_Profile(str):
    """CIS Requirements Profile"""

    Level_1 = "Level 1"
    Level_2 = "Level 2"


class CIS_Requirements_AssessmentStatus(str):
    """CIS Requirements Assessment Status"""

    Manual = "Manual"
    Automated = "Automated"


# CIS Requirements
class CIS_Requirements(BaseModel):
    """CIS Requirements"""

    Section: str
    Profile: CIS_Requirements_Profile
    AssessmentStatus: CIS_Requirements_AssessmentStatus
    Description: str
    RationaleStatement: str
    ImpactStatement: str
    RemediationProcedure: str
    AuditProcedure: str
    AdditionalInformation: str
    References: str

# Well Architected Requirements
class Well_Architected_Requirements(BaseModel):
    """Well Architected Requirements"""

    Name: str
    WellArchitectedWellArchitectedQuestionId: str
    WellArchitectedWellArchitectedPracticeId: str
    

# Base Compliance Model
class Compliance_Requirement(BaseModel):
    """Compliance_Requirement holds the base model for every requirement within a compliance framework"""

    Id: str
    Description: str
    Name: Optional[str]
    Attributes: list[
        Union[CIS_Requirements, ENS_Requirements, Generic_Compliance_Requirements]
    ]
    Checks: list[str]


class Compliance_Base_Model(BaseModel):
    """Compliance_Base_Model holds the base model for every compliance framework"""

    Framework: str
    Provider: str
    Version: Optional[str]
    Description: str
    Requirements: list[Compliance_Requirement]

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
