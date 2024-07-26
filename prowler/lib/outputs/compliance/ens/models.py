from pydantic import BaseModel


class AWSENSModel(BaseModel):
    """
    AWSENSModel generates a finding's output in CSV ENS format for AWS.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_IdGrupoControl: str
    Requirements_Attributes_Marco: str
    Requirements_Attributes_Categoria: str
    Requirements_Attributes_DescripcionControl: str
    Requirements_Attributes_Nivel: str
    Requirements_Attributes_Tipo: str
    Requirements_Attributes_Dimensiones: str
    Requirements_Attributes_ModoEjecucion: str
    Requirements_Attributes_Dependencias: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool
    ResourceName: str
