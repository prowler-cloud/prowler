#!/usr/bin/env python3
"""
Generate FastMCP server code from OpenAPI specification.

This script parses an OpenAPI specification file and generates FastMCP tool functions
with proper type hints, parameters, and docstrings.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
import yaml
from prowler_mcp_server.lib.logger import logger


class OpenAPIToMCPGenerator:
    def __init__(
        self,
        spec_file: str,
        custom_auth_module: Optional[str] = None,
        exclude_patterns: Optional[List[str]] = None,
        exclude_operations: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        include_only_tags: Optional[List[str]] = None,
        config_file: Optional[str] = None,
    ):
        """
        Initialize the generator with an OpenAPI spec file.

        Args:
            spec_file: Path to OpenAPI specification file
            custom_auth_module: Module path for custom authentication
            exclude_patterns: List of regex patterns to exclude endpoints (matches against path)
            exclude_operations: List of operation IDs to exclude
            exclude_tags: List of tags to exclude
            include_only_tags: If specified, only include endpoints with these tags
            config_file: Path to JSON configuration file for custom mappings
        """
        self.spec_file = spec_file
        self.custom_auth_module = custom_auth_module
        self.exclude_patterns = exclude_patterns or []
        self.exclude_operations = exclude_operations or []
        self.exclude_tags = exclude_tags or []
        self.include_only_tags = include_only_tags
        self.config_file = config_file
        self.config = self._load_config() if config_file else {}
        self.spec = self._load_spec()
        self.generated_tools = []
        self.imports = set()
        self.type_mapping = {
            "string": "str",
            "integer": "int",
            "number": "float",
            "boolean": "bool",
            "array": "str",
            "object": "Dict[str, Any]",
        }

    def _load_config(self) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(self.config_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            # print(f"Warning: Config file {self.config_file} not found. Using defaults.")
            return {}
        except json.JSONDecodeError:
            # print(f"Warning: Error parsing config file: {e}. Using defaults.")
            return {}

    def _load_spec(self) -> Dict:
        """Load OpenAPI specification from file."""
        with open(self.spec_file, "r") as f:
            if self.spec_file.endswith(".yaml") or self.spec_file.endswith(".yml"):
                return yaml.safe_load(f)
            else:
                return json.load(f)

    def _get_endpoint_config(self, path: str, method: str) -> Dict:
        """Get endpoint configuration from config file with pattern matching and inheritance.

        Configuration resolution order (most to least specific):
        1. Exact endpoint match (e.g., "GET /api/v1/findings/metadata")
        2. Pattern matches, sorted by specificity:
           - Patterns without wildcards are more specific
           - Longer patterns are more specific
           - Example: "GET /api/v1/findings/*" matches all findings endpoints

        When multiple configurations match, they are merged with more specific
        configurations overriding less specific ones.
        """
        if not self.config:
            return {}

        endpoint_key = f"{method.upper()} {path}"
        merged_config = {}

        # Get endpoints configuration (now supports both exact and pattern matches)
        endpoints = self.config.get("endpoints", {})

        # Separate exact matches from patterns
        exact_match = None
        pattern_matches = []

        for config_key, config_value in endpoints.items():
            if "*" in config_key or "?" in config_key:
                # This is a pattern - convert wildcards to regex
                regex_pattern = config_key.replace("*", ".*").replace("?", ".")
                if re.match(f"^{regex_pattern}$", endpoint_key):
                    pattern_matches.append((config_key, config_value))
            elif config_key == endpoint_key:
                # Exact match
                exact_match = (config_key, config_value)

        # Also check for patterns in endpoint_patterns for backward compatibility
        endpoint_patterns = self.config.get("endpoint_patterns", {})
        for pattern, pattern_config in endpoint_patterns.items():
            regex_pattern = pattern.replace("*", ".*").replace("?", ".")
            if re.match(f"^{regex_pattern}$", endpoint_key):
                pattern_matches.append((pattern, pattern_config))

        # Sort pattern matches by specificity
        # More specific patterns should be applied last to override less specific ones
        pattern_matches.sort(
            key=lambda x: (
                x[0].count("*") + x[0].count("?"),  # Fewer wildcards = more specific
                -len(
                    x[0]
                ),  # Longer patterns = more specific (negative for reverse sort)
            ),
            reverse=True,
        )  # Reverse so least specific comes first

        # Apply configurations from least to most specific
        # First apply pattern matches (from least to most specific)
        for pattern, pattern_config in pattern_matches:
            merged_config = self._merge_configs(merged_config, pattern_config)

        # Finally apply exact match (most specific)
        if exact_match:
            merged_config = self._merge_configs(merged_config, exact_match[1])

        # Fallback to old endpoint_mappings for backward compatibility
        if not merged_config:
            endpoint_mappings = self.config.get("endpoint_mappings", {})
            if endpoint_key in endpoint_mappings:
                merged_config = {"name": endpoint_mappings[endpoint_key]}

        return merged_config

    def _merge_configs(self, base_config: Dict, override_config: Dict) -> Dict:
        """Merge two configurations, with override_config taking precedence.

        Special handling for parameters: merges parameter configurations deeply.
        """
        import copy

        result = copy.deepcopy(base_config)

        for key, value in override_config.items():
            if key == "parameters" and key in result:
                # Deep merge parameters
                if not isinstance(result[key], dict):
                    result[key] = {}
                if isinstance(value, dict):
                    for param_name, param_config in value.items():
                        if param_name in result[key] and isinstance(
                            result[key][param_name], dict
                        ):
                            # Merge parameter configurations
                            result[key][param_name] = {
                                **result[key][param_name],
                                **param_config,
                            }
                        else:
                            result[key][param_name] = param_config
            else:
                # For other keys, override completely
                result[key] = value

        return result

    def _sanitize_function_name(self, operation_id: str) -> str:
        """Convert operation ID to valid Python function name."""
        # Replace non-alphanumeric characters with underscores
        name = re.sub(r"[^a-zA-Z0-9_]", "_", operation_id)
        # Ensure it doesn't start with a number
        if name and name[0].isdigit():
            name = f"op_{name}"
        return name.lower()

    def _get_python_type(self, schema: Dict) -> str:
        """Convert OpenAPI schema to Python type hint."""
        if not schema:
            return "Any"

        # Handle oneOf/anyOf/allOf schemas - these are typically objects
        if "oneOf" in schema or "anyOf" in schema or "allOf" in schema:
            # These are complex schemas, typically representing different object variants
            return "Dict[str, Any]"

        schema_type = schema.get("type", "string")

        # Handle enums
        if "enum" in schema:
            enum_values = schema["enum"]
            if all(isinstance(v, str) for v in enum_values):
                # Create Literal type for string enums
                self.imports.add("from typing import Literal")
                enum_str = ", ".join(f'"{v}"' for v in enum_values)
                return f"Literal[{enum_str}]"
            else:
                return self.type_mapping.get(schema_type, "Any")

        # Handle arrays
        if schema_type == "array":
            return "str"

        # Handle format specifications
        if schema_type == "string":
            format_type = schema.get("format", "")
            if format_type in ["date", "date-time"]:
                return "str"  # Keep as string for API calls
            elif format_type == "uuid":
                return "str"
            elif format_type == "email":
                return "str"

        return self.type_mapping.get(schema_type, "Any")

    def _resolve_ref(self, ref: str) -> Dict:
        """Resolve a $ref reference in the OpenAPI spec."""
        if not ref.startswith("#/"):
            return {}

        # Split the reference path
        ref_parts = ref[2:].split("/")  # Remove '#/' and split

        # Navigate through the spec to find the referenced schema
        resolved = self.spec
        for part in ref_parts:
            resolved = resolved.get(part, {})

        return resolved

    def _extract_parameters(
        self, operation: Dict, endpoint_config: Optional[Dict] = None
    ) -> List[Dict]:
        """Extract and process parameters from an operation."""
        parameters = []

        for param in operation.get("parameters", []):
            # Sanitize parameter name for Python
            python_name = (
                param.get("name", "")
                .replace("[", "_")
                .replace("]", "")
                .replace(".", "_")
                .replace("-", "_")
            )  # Also replace hyphens

            param_info = {
                "name": param.get("name", ""),
                "python_name": python_name,
                "in": param.get("in", "query"),
                "required": param.get("required", False),
                "description": param.get("description", ""),
                "type": self._get_python_type(param.get("schema", {})),
                "original_schema": param.get("schema", {}),
            }

            # Apply custom parameter configuration from endpoint config
            if endpoint_config and "parameters" in endpoint_config:
                param_config = endpoint_config["parameters"]
                if param_info["name"] in param_config:
                    custom_param = param_config[param_info["name"]]
                    if "name" in custom_param:
                        param_info["python_name"] = custom_param["name"]
                    if "description" in custom_param:
                        param_info["description"] = custom_param["description"]

            parameters.append(param_info)

        # Handle request body if present - extract as individual parameters
        if "requestBody" in operation:
            body = operation["requestBody"]
            content = body.get("content", {})

            # Check for different content types
            schema = None
            if "application/vnd.api+json" in content:
                schema = content["application/vnd.api+json"].get("schema", {})
            elif "application/json" in content:
                schema = content["application/json"].get("schema", {})

            if schema:
                # Resolve $ref if present
                if "$ref" in schema:
                    schema = self._resolve_ref(schema["$ref"])

                # Try to extract individual fields from the schema
                body_params = self._extract_body_parameters(
                    schema, body.get("required", False)
                )

                # Apply custom parameter config to body parameters
                if endpoint_config and "parameters" in endpoint_config:
                    param_config = endpoint_config["parameters"]
                    for param in body_params:
                        if param["name"] in param_config:
                            custom_param = param_config[param["name"]]
                            if "name" in custom_param:
                                param["python_name"] = custom_param["name"]
                            if "description" in custom_param:
                                param["description"] = custom_param["description"]

                parameters.extend(body_params)

        return parameters

    def _extract_body_parameters(self, schema: Dict, is_required: bool) -> List[Dict]:
        """Extract individual parameters from request body schema."""
        parameters = []

        # Handle JSON:API format with data.attributes structure
        if "properties" in schema:
            data = schema["properties"].get("data", {})
            if "properties" in data:
                # Extract attributes
                attributes = data["properties"].get("attributes", {})
                if "properties" in attributes:
                    # Get required fields from attributes
                    required_attrs = attributes.get("required", [])

                    for prop_name, prop_schema in attributes["properties"].items():
                        # Skip read-only fields for POST/PUT/PATCH operations
                        if prop_schema.get("readOnly", False):
                            continue

                        python_name = prop_name.replace("-", "_")
                        # Check if this field is required
                        is_field_required = prop_name in required_attrs

                        param_info = {
                            "name": prop_name,  # Keep original name for API
                            "python_name": python_name,
                            "in": "body",
                            "required": is_field_required,
                            "description": prop_schema.get(
                                "description",
                                prop_schema.get("title", f"{prop_name} parameter"),
                            ),
                            "type": self._get_python_type(prop_schema),
                            "original_schema": prop_schema,
                            "resource_type": (
                                data["properties"]
                                .get("type", {})
                                .get("enum", ["resource"])[0]
                                if "type" in data["properties"]
                                else "resource"
                            ),
                        }
                        parameters.append(param_info)

                # Also check for relationships (like provider_id)
                relationships = data["properties"].get("relationships", {})
                if "properties" in relationships:
                    required_rels = relationships.get("required", [])
                    for rel_name, rel_schema in relationships["properties"].items():
                        # Extract ID from relationship
                        python_name = f"{rel_name}_id"
                        is_rel_required = rel_name in required_rels

                        param_info = {
                            "name": f"{rel_name}_id",
                            "python_name": python_name,
                            "in": "body",
                            "required": is_rel_required,
                            "description": f"ID of the related {rel_name}",
                            "type": "str",
                            "original_schema": rel_schema,
                        }
                        parameters.append(param_info)

        # If no structured params found, fall back to generic body parameter
        if not parameters and schema:
            parameters.append(
                {
                    "name": "body",
                    "python_name": "body",
                    "in": "body",
                    "required": is_required,
                    "description": "Request body data",
                    "type": "Dict[str, Any]",
                    "original_schema": schema,
                }
            )

        return parameters

    def _generate_docstring(
        self,
        operation: Dict,
        parameters: List[Dict],
        path: str,
        method: str,
        endpoint_config: Optional[Dict] = None,
    ) -> str:
        """Generate a comprehensive docstring for the tool function."""
        lines = []

        # Main description - use custom or default
        endpoint_config = endpoint_config or {}

        # Use custom description if provided, otherwise fall back to OpenAPI
        if "description" in endpoint_config:
            lines.append(f'    """{endpoint_config["description"]}')
        else:
            summary = operation.get("summary", "")
            description = operation.get("description", "")
            if summary:
                lines.append(f'    """{summary}')
            else:
                lines.append(f'    """Execute {method.upper()} {path}')

        if "description" not in endpoint_config:
            # Only add OpenAPI description if no custom description was provided
            description = operation.get("description", "")
            if description and description != summary:
                lines.append("")
                # Clean up description - remove extra whitespace
                clean_desc = " ".join(description.split())
                lines.append(f"    {clean_desc}")

        # Add endpoint info
        lines.append("")
        lines.append(f"    Endpoint: {method.upper()} {path}")

        # Parameters section
        if parameters:
            lines.append("")
            lines.append("    Args:")
            for param in parameters:
                # Use custom description if available
                param_desc = param["description"] or "No description provided"

                # Handle multi-line descriptions properly
                required_text = "(required)" if param["required"] else "(optional)"

                if "\n" in param_desc:
                    # Split on actual newlines (not escaped)
                    desc_lines = param_desc.split("\n")
                    first_line = desc_lines[0].strip()
                    lines.append(
                        f"        {param['python_name']} {required_text}: {first_line}"
                    )
                    # Add subsequent lines with proper indentation (12 spaces for continuation)
                    for desc_line in desc_lines[1:]:
                        desc_line = desc_line.strip()
                        if desc_line:
                            lines.append(f"            {desc_line}")
                else:
                    # Clean up parameter description for single line
                    param_desc = " ".join(param_desc.split())
                    lines.append(
                        f"        {param['python_name']} {required_text}: {param_desc}"
                    )

                # Add enum values if present
                if "enum" in param.get("original_schema", {}):
                    enum_values = param["original_schema"]["enum"]
                    lines.append(
                        f"            Allowed values: {', '.join(str(v) for v in enum_values)}"
                    )

        # Returns section
        lines.append("")
        lines.append("    Returns:")
        lines.append("        Dict containing the API response")

        lines.append('    """')
        return "\n".join(lines)

    def _generate_function_signature(
        self, func_name: str, parameters: List[Dict]
    ) -> str:
        """Generate the function signature with proper type hints."""
        # Sort parameters: required first, then optional
        sorted_params = sorted(
            parameters, key=lambda x: (not x["required"], x["python_name"])
        )

        param_strings = []
        for param in sorted_params:
            if param["required"]:
                param_strings.append(f"    {param['python_name']}: {param['type']}")
            else:
                param_strings.append(
                    f"    {param['python_name']}: Optional[{param['type']}] = None"
                )

        if param_strings:
            params_str = ",\n".join(param_strings)
            return f"async def {func_name}(\n{params_str}\n) -> Dict[str, Any]:"
        else:
            return f"async def {func_name}() -> Dict[str, Any]:"

    def _generate_function_body(
        self, path: str, method: str, parameters: List[Dict], operation_id: str
    ) -> str:
        """Generate the function body for making API calls."""
        lines = []

        # Add try block
        lines.append("    try:")

        # Get authentication token if custom auth module is provided
        if self.custom_auth_module:
            lines.append("        token = await auth_manager.get_valid_token()")
            lines.append("")

        # Build parameters
        query_params = [p for p in parameters if p["in"] == "query"]
        path_params = [p for p in parameters if p["in"] == "path"]
        body_params = [p for p in parameters if p["in"] == "body"]

        # Build query parameters
        if query_params:
            lines.append("        params = {}")
            for param in query_params:
                if param["required"]:
                    lines.append(
                        f"        params['{param['name']}'] = {param['python_name']}"
                    )
                else:
                    lines.append(f"        if {param['python_name']} is not None:")
                    lines.append(
                        f"            params['{param['name']}'] = {param['python_name']}"
                    )
            lines.append("")

        # Build path with path parameters
        final_path = path
        for param in path_params:
            lines.append(
                f"        path = '{path}'.replace('{{{param['name']}}}', str({param['python_name']}))"
            )
            final_path = "path"

        # Build request body if there are body parameters
        if body_params:
            # Check if we have individual params or a single body param
            if len(body_params) == 1 and body_params[0]["python_name"] == "body":
                # Single body parameter - use it directly
                lines.append("        request_body = body")
            else:
                # Get resource type from first body param (they should all have the same)
                resource_type = (
                    body_params[0].get("resource_type", "resource")
                    if body_params
                    else "resource"
                )

                # Build JSON:API structure from individual parameters
                lines.append("        # Build request body")
                lines.append("        request_body = {")
                lines.append('            "data": {')
                lines.append(f'                "type": "{resource_type}"')

                # Separate attributes from relationships
                # Note: Check if param was originally from attributes section, not just by name
                attribute_params = []
                relationship_params = []

                for p in body_params:
                    # If this param came from the attributes section (has resource_type), it's an attribute
                    # even if its name ends with _id
                    if "resource_type" in p:
                        attribute_params.append(p)
                    elif p["python_name"].endswith("_id") and "resource_type" not in p:
                        relationship_params.append(p)
                    else:
                        attribute_params.append(p)

                if attribute_params:
                    lines.append(",")
                    lines.append('                "attributes": {}')

                lines.append("            }")
                lines.append("        }")

                if attribute_params:
                    lines.append("")
                    lines.append("        # Add attributes")
                    for param in attribute_params:
                        if param["required"]:
                            lines.append(
                                f'        request_body["data"]["attributes"]["{param["name"]}"] = {param["python_name"]}'
                            )
                        else:
                            lines.append(
                                f"        if {param['python_name']} is not None:"
                            )
                            lines.append(
                                f'            request_body["data"]["attributes"]["{param["name"]}"] = {param["python_name"]}'
                            )

                if relationship_params:
                    lines.append("")
                    lines.append("        # Add relationships")
                    lines.append('        request_body["data"]["relationships"] = {}')
                    for param in relationship_params:
                        rel_name = param["python_name"].replace("_id", "")
                        if param["required"]:
                            lines.append(
                                f'        request_body["data"]["relationships"]["{rel_name}"] = {{'
                            )
                            lines.append('            "data": {')
                            lines.append(f'                "type": "{rel_name}s",')
                            lines.append(
                                f'                "id": {param["python_name"]}'
                            )
                            lines.append("            }")
                            lines.append("        }")
                        else:
                            lines.append(
                                f"        if {param['python_name']} is not None:"
                            )
                            lines.append(
                                f'            request_body["data"]["relationships"]["{rel_name}"] = {{'
                            )
                            lines.append('                "data": {')
                            lines.append(f'                    "type": "{rel_name}s",')
                            lines.append(
                                f'                    "id": {param["python_name"]}'
                            )
                            lines.append("                }")
                            lines.append("            }")
            lines.append("")

        # Prepare HTTP client call
        lines.append("        async with httpx.AsyncClient() as client:")

        # Build the request
        request_params = [
            (
                f'f"{{auth_manager.base_url}}{{{final_path}}}"'
                if final_path == "path"
                else f'f"{{auth_manager.base_url}}{path}"'
            )
        ]

        if self.custom_auth_module:
            request_params.append("headers=auth_manager.get_headers(token)")

        if query_params:
            request_params.append("params=params")

        if body_params:
            request_params.append("json=request_body")

        request_params.append("timeout=30.0")

        params_str = ",\n                ".join(request_params)

        lines.append(f"            response = await client.{method}(")
        lines.append(f"                {params_str}")
        lines.append("            )")
        lines.append("            response.raise_for_status()")
        lines.append("")

        # Parse response
        lines.append("            data = response.json()")
        lines.append("")
        lines.append("            return {")
        lines.append('                "success": True,')
        lines.append('                "data": data.get("data", data),')
        lines.append('                "meta": data.get("meta", {})')
        lines.append("            }")
        lines.append("")

        # Exception handling
        lines.append("    except Exception as e:")
        lines.append("        return {")
        lines.append('            "success": False,')
        lines.append(
            f'            "error": f"Failed to execute {operation_id}: {{str(e)}}"'
        )
        lines.append("        }")

        return "\n".join(lines)

    def _should_exclude_endpoint(self, path: str, operation: Dict) -> bool:
        """
        Determine if an endpoint should be excluded from generation.

        Args:
            path: The API endpoint path
            operation: The operation dictionary from OpenAPI spec

        Returns:
            True if endpoint should be excluded, False otherwise
        """
        # Check if operation is marked as deprecated
        if operation.get("deprecated", False):
            return True

        # Check operation ID exclusion
        operation_id = operation.get("operationId", "")
        if operation_id in self.exclude_operations:
            return True

        # Check path pattern exclusion
        for pattern in self.exclude_patterns:
            if re.search(pattern, path):
                return True

        # Check tags
        tags = operation.get("tags", [])

        # If include_only_tags is specified, exclude if no matching tag
        if self.include_only_tags:
            if not any(tag in self.include_only_tags for tag in tags):
                return True

        # Check excluded tags
        if any(tag in self.exclude_tags for tag in tags):
            logger.debug(f"Excluding endpoint {path} due to tag {tags}")
            return True

        return False

    def generate_tools(self) -> str:
        """Generate all FastMCP tools from the OpenAPI spec."""
        output_lines = []

        # Generate header
        output_lines.append('"""')
        output_lines.append("Auto-generated FastMCP server from OpenAPI specification")
        output_lines.append(f"Generated on: {datetime.now().isoformat()}")
        output_lines.append(
            f"Source: {self.spec_file} (version: {self.spec.get('info', {}).get('version', 'unknown')})"
        )
        output_lines.append('"""')
        output_lines.append("")

        # Add imports
        self.imports.add("from typing import Dict, Any, Optional")
        self.imports.add("import httpx")
        self.imports.add("from fastmcp import FastMCP")

        if self.custom_auth_module:
            self.imports.add(f"from {self.custom_auth_module} import ProwlerAppAuth")

        # Process all paths and operations
        paths = self.spec.get("paths", {})

        tools_by_tag = {}  # Group tools by tag for better organization
        excluded_count = 0

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete"]:
                if method in path_item:
                    operation = path_item[method]

                    # Check if this endpoint should be excluded
                    if self._should_exclude_endpoint(path, operation):
                        excluded_count += 1
                        continue

                    operation_id = operation.get("operationId", f"{method}_{path}")
                    tags = operation.get("tags", ["default"])

                    # Get endpoint configuration
                    endpoint_config = self._get_endpoint_config(path, method)

                    # Use custom function name if provided
                    if "name" in endpoint_config:
                        func_name = endpoint_config["name"]
                    else:
                        func_name = self._sanitize_function_name(operation_id)

                    parameters = self._extract_parameters(operation, endpoint_config)

                    tool_code = []

                    # Add @app_mcp_server.tool() decorator
                    tool_code.append("@app_mcp_server.tool()")

                    # Generate function signature
                    tool_code.append(
                        self._generate_function_signature(func_name, parameters)
                    )

                    # Generate docstring with custom description if provided
                    tool_code.append(
                        self._generate_docstring(
                            operation, parameters, path, method, endpoint_config
                        )
                    )

                    # Generate function body
                    tool_code.append(
                        self._generate_function_body(
                            path, method, parameters, operation_id
                        )
                    )

                    # Group by tag
                    for tag in tags:
                        if tag not in tools_by_tag:
                            tools_by_tag[tag] = []
                        tools_by_tag[tag].append("\n".join(tool_code))

        # Write imports (consolidate typing imports)
        typing_imports = set()
        other_imports = []

        for imp in sorted(self.imports):
            if imp.startswith("from typing import"):
                # Extract the imported items
                items = imp.replace("from typing import", "").strip()
                typing_imports.update([item.strip() for item in items.split(",")])
            else:
                other_imports.append(imp)

        # Add consolidated typing import if needed
        if typing_imports:
            output_lines.append(
                f"from typing import {', '.join(sorted(typing_imports))}"
            )

        # Add other imports
        for imp in other_imports:
            output_lines.append(imp)

        output_lines.append("")
        output_lines.append("# Initialize MCP server")
        output_lines.append('app_mcp_server = FastMCP("prowler-app")')
        output_lines.append("")

        if self.custom_auth_module:
            output_lines.append("# Initialize authentication manager")
            output_lines.append("auth_manager = ProwlerAppAuth()")
            output_lines.append("")

        # Write tools grouped by tag
        for tag, tools in tools_by_tag.items():
            output_lines.append("")
            output_lines.append("# " + "=" * 76)
            output_lines.append(f"# {tag.upper()} ENDPOINTS")
            output_lines.append("# " + "=" * 76)
            output_lines.append("")

            for tool in tools:
                output_lines.append("")
                output_lines.append(tool)

        return "\n".join(output_lines)

    def save_to_file(self, output_file: str):
        """Save the generated code to a file."""
        generated_code = self.generate_tools()
        Path(output_file).write_text(generated_code)
        # print(f"Generated FastMCP server saved to: {output_file}")

        # # Report statistics
        # paths = self.spec.get("paths", {})
        # total_endpoints = sum(
        #     len(
        #         [m for m in ["get", "post", "put", "patch", "delete"] if m in path_item]
        #     )
        #     for path_item in paths.values()
        # )

        # # Count excluded endpoints by reason
        # excluded_count = 0
        # deprecated_count = 0
        # for path, path_item in paths.items():
        #     for method in ["get", "post", "put", "patch", "delete"]:
        #         if method in path_item:
        #             operation = path_item[method]
        #             if operation.get("deprecated", False):
        #                 deprecated_count += 1
        #             if self._should_exclude_endpoint(path, operation):
        #                 excluded_count += 1

        # generated_count = total_endpoints - excluded_count
        # print(f"Total endpoints in spec: {total_endpoints}")
        # print(f"Endpoints excluded: {excluded_count}")
        # if deprecated_count > 0:
        # print(f"  - Deprecated: {deprecated_count}")
        # print(f"Endpoints generated: {generated_count}")

        # Show exclusion rules if any
        # if self.exclude_patterns:
        #     # print(f"Excluded patterns: {self.exclude_patterns}")
        # if self.exclude_operations:
        #     # print(f"Excluded operations: {self.exclude_operations}")
        # if self.exclude_tags:
        #     # print(f"Excluded tags: {self.exclude_tags}")
        # if self.include_only_tags:
        #     # print(f"Including only tags: {self.include_only_tags}")


def generate_server_file():
    # Get the spec file from the API directly (https://api.prowler.com/api/v1/schema)
    api_base_url = os.getenv("PROWLER_API_BASE_URL", "https://api.prowler.com")
    spec_file = f"{api_base_url}/api/v1/schema"

    # Download the spec yaml file
    response = requests.get(spec_file)
    response.raise_for_status()
    spec_data = response.text

    # Save the spec data to a file
    with open(str(Path(__file__).parent / "schema.yaml"), "w") as f:
        f.write(spec_data)

    # Example usage
    generator = OpenAPIToMCPGenerator(
        spec_file=str(Path(__file__).parent / "schema.yaml"),
        custom_auth_module="prowler_mcp_server.prowler_app.utils.auth",
        include_only_tags=[
            "Provider",
            "Scan",
            "Schedule",
            "Finding",
            "Processor",
        ],
        config_file=str(
            Path(__file__).parent / "mcp_config.json"
        ),  # Use custom naming config
    )

    # Generate and save the MCP server
    generator.save_to_file(str(Path(__file__).parent.parent / "server.py"))


if __name__ == "__main__":
    generate_server_file()
