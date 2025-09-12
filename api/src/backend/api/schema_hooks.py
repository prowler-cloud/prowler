from api.utils import (
    FIELDS_PARAMETER_DESCRIPTION,
    INSERTED_AT_FILTER_PARAMETER_DESCRIPTION,
)


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


def customize_parameter_descriptions(result, generator, request, public):  # noqa: F841
    """Customize parameter descriptions based on parameter name patterns.

    This function applies consistent descriptions to common parameter types across all endpoints.
    To add new parameter rules, simply add them to the parameter_rules dictionary.
    """
    if not isinstance(result, dict):
        return result

    # Define parameter customization rules
    # Each rule maps a condition function to its description
    parameter_rules = {
        # Fields parameters: fields[resource_type] - static description
        lambda name: name.startswith("fields[")
        and name.endswith("]"): FIELDS_PARAMETER_DESCRIPTION,
        # Inserted at filter: filter[inserted_at] - static description
        lambda name: name
        == "filter[inserted_at]": INSERTED_AT_FILTER_PARAMETER_DESCRIPTION,
        # Add more rules here as needed:
        # lambda name: name == "filter[updated_at]": "Filter by exact date when the resource was updated...",
        # lambda name: name.startswith("filter[status]"): "Filter by resource status...",
    }

    paths = result.get("paths", {}) or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue

        for method_obj in path_item.values():
            if not isinstance(method_obj, dict):
                continue

            parameters = method_obj.get("parameters", []) or []
            for param in parameters:
                if not isinstance(param, dict):
                    continue

                param_name = param.get("name", "")

                # Apply parameter rules
                for condition_func, description in parameter_rules.items():
                    if condition_func(param_name):
                        param["description"] = description
                        break  # Only apply the first matching rule

    return result
