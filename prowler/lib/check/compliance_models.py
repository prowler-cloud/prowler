import sys
from enum import Enum
from typing import Any, List, Optional, Union

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


class ENS_Requirements(BaseModel):
    """ENS V3 Framework Requirements"""

    IdGrupoControl: str
    Marco: str
    Categoria: str
    Descripcion_Control: str
    Nivel: list[ENS_Requirements_Nivel]
    Dimensiones: list[ENS_Requirements_Dimensiones]


# Base Compliance Model
class Compliance_Requirement(BaseModel):
    """Compliance_Requirement holds the base model for every requirement within a compliance framework"""

    Id: str
    Description: str
    Attributes: list[Union[ENS_Requirements, Any]]
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
