from drf_spectacular.utils import extend_schema_field

from api.v1.serializer_utils.base import YamlOrJsonField


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "Mutelist",
                "properties": {
                    "whatthehellisthis": {
                        "type": "string",
                        "description": "TODO",
                    },
                },
            },
        ]
    }
)
class ProcessorConfigField(YamlOrJsonField):
    pass
