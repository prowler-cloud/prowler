def _pick_task_response_component(components):
    schemas = components.get("schemas", {}) or {}
    for candidate in ("TaskResponse",):
        if candidate in schemas:
            return candidate
    return None


def _extract_task_example_from_components(components):
    schemas = components.get("schemas", {}) or {}
    candidate = "TaskResponse"
    doc = schemas.get(candidate)
    if isinstance(doc, dict) and "example" in doc:
        return doc["example"]

    res = schemas.get(candidate)
    if isinstance(res, dict) and "example" in res:
        example = res["example"]
        return example if "data" in example else {"data": example}

    # Fallback
    return {
        "data": {
            "type": "tasks",
            "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08",
            "attributes": {
                "inserted_at": "2019-08-24T14:15:22Z",
                "completed_at": "2019-08-24T14:15:22Z",
                "name": "string",
                "state": "available",
                "result": None,
                "task_args": None,
                "metadata": None,
            },
        }
    }


def fix_empty_id_fields(result, generator, request, public):  # noqa: F841
    """
    Fix empty id fields in JSON:API request schemas.
    drf-spectacular-jsonapi sometimes generates empty id field definitions ({})
    which cause validation errors in Mintlify and other OpenAPI validators.
    """
    if not isinstance(result, dict):
        return result

    components = result.get("components", {}) or {}
    schemas = components.get("schemas", {}) or {}

    for schema_name, schema in schemas.items():
        if not isinstance(schema, dict):
            continue

        # Check if this is a JSON:API request schema with a data object
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            continue

        data_prop = properties.get("data")
        if not isinstance(data_prop, dict):
            continue

        data_properties = data_prop.get("properties", {})
        if not isinstance(data_properties, dict):
            continue

        # Fix empty id field
        id_field = data_properties.get("id")
        if id_field == {} or (isinstance(id_field, dict) and not id_field):
            data_properties["id"] = {
                "type": "string",
                "format": "uuid",
                "description": "Unique identifier for this resource object.",
            }

    return result


def convert_pattern_properties_to_additional(obj):
    """
    Recursively convert patternProperties to additionalProperties.
    OpenAPI 3.0.x doesn't support patternProperties (only available in 3.1+).
    """
    if isinstance(obj, dict):
        if "patternProperties" in obj:
            # Get the pattern and its schema
            pattern_props = obj.pop("patternProperties")
            # Use the first pattern's schema as additionalProperties
            if pattern_props:
                first_pattern_schema = next(iter(pattern_props.values()))
                obj["additionalProperties"] = first_pattern_schema

        # Recursively process all nested objects
        for key, value in obj.items():
            obj[key] = convert_pattern_properties_to_additional(value)
    elif isinstance(obj, list):
        return [convert_pattern_properties_to_additional(item) for item in obj]

    return obj


def fix_pattern_properties(result, generator, request, public):  # noqa: F841
    """
    Convert patternProperties to additionalProperties for OpenAPI 3.0 compatibility.
    patternProperties is only supported in OpenAPI 3.1+, but drf-spectacular
    generates OpenAPI 3.0.x specs.
    """
    if not isinstance(result, dict):
        return result

    return convert_pattern_properties_to_additional(result)


def fix_invalid_types(obj):
    """
    Recursively fix invalid type values in OpenAPI schemas.
    Converts invalid types like "email" to proper OpenAPI format.
    """
    if isinstance(obj, dict):
        # Fix invalid "type" values
        if "type" in obj:
            type_value = obj["type"]
            if type_value == "email":
                obj["type"] = "string"
                obj["format"] = "email"
            elif type_value == "url":
                obj["type"] = "string"
                obj["format"] = "uri"
            elif type_value == "uuid":
                obj["type"] = "string"
                obj["format"] = "uuid"

        # Recursively process all nested objects
        for key, value in list(obj.items()):
            obj[key] = fix_invalid_types(value)
    elif isinstance(obj, list):
        return [fix_invalid_types(item) for item in obj]

    return obj


def fix_type_formats(result, generator, request, public):  # noqa: F841
    """
    Fix invalid type values in OpenAPI schemas.
    drf-spectacular sometimes generates invalid type values like "email"
    instead of "type": "string" with "format": "email".
    """
    if not isinstance(result, dict):
        return result

    return fix_invalid_types(result)


def attach_task_202_examples(result, generator, request, public):  # noqa: F841
    if not isinstance(result, dict):
        return result

    components = result.get("components", {}) or {}
    task_resp_component = _pick_task_response_component(components)
    task_example = _extract_task_example_from_components(components)

    paths = result.get("paths", {}) or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue

        for method_obj in path_item.values():
            if not isinstance(method_obj, dict):
                continue

            responses = method_obj.get("responses", {}) or {}
            resp_202 = responses.get("202")
            if not isinstance(resp_202, dict):
                continue

            content = resp_202.get("content", {}) or {}
            jsonapi = content.get("application/vnd.api+json")
            if not isinstance(jsonapi, dict):
                continue

            # Inject example if missing
            if "examples" not in jsonapi and "example" not in jsonapi:
                jsonapi["examples"] = {
                    "Task queued": {
                        "summary": "Task queued",
                        "value": task_example,
                    }
                }

            # Rewrite schema $ref if needed
            if task_resp_component:
                schema = jsonapi.get("schema")
                must_replace = False
                if not isinstance(schema, dict):
                    must_replace = True
                else:
                    ref = schema.get("$ref")
                    if not ref:
                        must_replace = True
                    else:
                        current = ref.split("/")[-1]
                        if current != task_resp_component:
                            must_replace = True

                if must_replace:
                    jsonapi["schema"] = {
                        "$ref": f"#/components/schemas/{task_resp_component}"
                    }

    return result
