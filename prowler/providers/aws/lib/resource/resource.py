import re
from typing import List, Optional

from pydantic import Field, root_validator, validator

from prowler.lib.resource.resource import Resource

_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>[^:]*):(?P<service>[^:]*):"
    r"(?P<region>[^:]*):(?P<account>[^:]*):(?P<resource_id>.+)$"
)


class AWSResource(Resource):
    """
    Represents an AWS resource with its associated attributes.
    Attributes:
        arn (str): The Amazon Resource Name (ARN) uniquely identifying the resource.
        id (str): The unique identifier of the resource.
    """

    arn: str
    id: Optional[str] = None
    name: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    region: str

    @root_validator(pre=True)
    def populate_from_arn(cls, values):
        arn = values.get("arn")
        if arn:
            match = _ARN_PATTERN.match(arn)
            if not match:
                raise ValueError(f"Invalid ARN: {arn!r}")
            # Only overwrite if not provided explicitly
            values.setdefault("service", match.group("service"))
            values.setdefault("region", match.group("region"))
            # Extract the last part after the '/' if it exists
            resource_id = match.group("resource_id")
            values.setdefault(
                "id", resource_id.split("/")[-1] if "/" in resource_id else resource_id
            )
        return values

    @validator("region")
    def region_must_be_valid(cls, v):
        if not v:
            raise ValueError("region cannot be empty")
        return v
