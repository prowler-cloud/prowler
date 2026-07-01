from pydantic import BaseModel


class Resource(BaseModel):
    """
    Represents a generic resource.

    Attributes:
        service (str): The name of the service associated with the resource.
    """

    service: str
