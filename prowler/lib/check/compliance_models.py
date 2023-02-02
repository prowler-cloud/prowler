import sys
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ValidationError

from prowler.lib.logger import logger


# ENS - Esquema Nacional de Seguridad - España
class ENS_Requirements_Nivel(str, Enum):
    """ENS V3 Requirements Level"""

    bajo = "bajo"
    medio = "medio"
    alto = "alto"
    pytec = "pytec"


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

    IdGrupoControl: Optional[str]
    Marco: str
    Categoria: str
    DescripcionControl: str
    Tipo: ENS_Requirements_Tipos
    Nivel: ENS_Requirements_Nivel
    Dimensiones: list[ENS_Requirements_Dimensiones]


# General Compliance Requirements
class General_Compliance_Requirements(BaseModel):
    """General Compliance Requirements"""

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


# Base Compliance Model
class Compliance_Requirement(BaseModel):
    """Compliance_Requirement holds the base model for every requirement within a compliance framework"""

    Id: str
    Description: str
    Attributes: list[Union[CIS_Requirements, ENS_Requirements, General_Compliance_Requirements]]
    Checks: List[str]


class Compliance_Base_Model(BaseModel):
    """Compliance_Base_Model holds the base model for every compliance framework"""

    Framework: str
    Provider: Optional[str]
    Version: str
    Requirements: list[Compliance_Requirement]


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
        sys.exit()
    else:
        return compliance_framework
