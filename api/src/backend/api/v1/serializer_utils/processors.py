from drf_spectacular.utils import extend_schema_field

from api.v1.serializer_utils.base import YamlOrJsonField


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "Mutelist",
                "properties": {
                    "Mutelist": {
                        "properties": {
                            "Accounts": {
                                "patternProperties": {
                                    ".*": {
                                        "properties": {
                                            "Checks": {
                                                "patternProperties": {
                                                    ".*": {
                                                        "properties": {
                                                            "Exceptions": {
                                                                "properties": {
                                                                    "Accounts": {
                                                                        "items": {
                                                                            "type": "string"
                                                                        },
                                                                        "type": "array",
                                                                    },
                                                                    "Regions": {
                                                                        "items": {
                                                                            "type": "string"
                                                                        },
                                                                        "type": "array",
                                                                    },
                                                                    "Resources": {
                                                                        "items": {
                                                                            "type": "string"
                                                                        },
                                                                        "type": "array",
                                                                    },
                                                                    "Tags": {
                                                                        "items": {
                                                                            "type": "string"
                                                                        },
                                                                        "type": "array",
                                                                    },
                                                                },
                                                                "required": [],
                                                                "type": "object",
                                                                "additionalProperties": False,
                                                            },
                                                            "Regions": {
                                                                "items": {
                                                                    "type": "string"
                                                                },
                                                                "type": "array",
                                                            },
                                                            "Resources": {
                                                                "items": {
                                                                    "type": "string"
                                                                },
                                                                "type": "array",
                                                            },
                                                            "Tags": {
                                                                "items": {
                                                                    "type": "string"
                                                                },
                                                                "type": "array",
                                                            },
                                                        },
                                                        "required": [
                                                            "Regions",
                                                            "Resources",
                                                        ],
                                                        "type": "object",
                                                        "additionalProperties": False,
                                                    }
                                                },
                                                "required": [],
                                                "type": "object",
                                            }
                                        },
                                        "required": ["Checks"],
                                        "type": "object",
                                        "additionalProperties": False,
                                    }
                                },
                                "required": [],
                                "type": "object",
                            }
                        },
                        "required": ["Accounts"],
                        "type": "object",
                        "additionalProperties": False,
                    }
                },
                "additionalProperties": False,
            },
        ]
    }
)
class ProcessorConfigField(YamlOrJsonField):
    pass
