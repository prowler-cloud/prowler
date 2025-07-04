from drf_spectacular.utils import extend_schema_field

from api.v1.serializer_utils.base import YamlOrJsonField

from prowler.lib.mutelist.mutelist import mutelist_schema


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "Mutelist",
                "properties": {"Mutelist": mutelist_schema},
                "additionalProperties": False,
            },
        ]
    }
)
class ProcessorConfigField(YamlOrJsonField):
    pass
