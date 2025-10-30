#!/usr/bin/env python3
"""
Prowler API Documentation Auto-Generator
Generates MDX files from OpenAPI specification

Usage:
    python3 generate-api-docs.py [--update-existing] [--dry-run]

Options:
    --update-existing  Update existing MDX files (default: skip existing files)
    --dry-run         Show what would be generated without writing files
    --help            Show this help message
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class APIDocGenerator:
    """Generate Mintlify MDX documentation from OpenAPI spec"""

    def __init__(self, openapi_file: str, api_reference_dir: str):
        self.openapi_file = openapi_file
        self.api_reference_dir = Path(api_reference_dir)
        self.spec = None
        self.stats = {"generated": 0, "updated": 0, "skipped": 0, "errors": 0}

    def load_spec(self):
        """Load OpenAPI specification"""
        print(f"📖 Loading OpenAPI spec from {self.openapi_file}")
        with open(self.openapi_file, "r") as f:
            self.spec = yaml.safe_load(f)
        print(f"✅ Loaded spec version {self.spec.get('info', {}).get('version')}")

    def operation_id_to_path(self, operation_id: str) -> Optional[str]:
        """Convert operation ID to file path

        Examples:
            providers_secrets_create -> providers/secrets/create.mdx
            tokens_create -> tokens/create.mdx
            users_memberships_list -> users/memberships-list.mdx
        """
        parts = operation_id.split("_")

        # Map operation IDs to directory names
        path_map = {
            "tokens": "tokens",
            "api_keys": "api-keys",
            "users": "users",
            "tenants": "tenants",
            "invitations": "invitations",
            "providers": "providers",
            "scans": "scans",
            "findings": "findings",
            "resources": "resources",
            "compliance": "compliance",
            "overviews": "overviews",
            "integrations": "integrations",
            "lighthouse": "lighthouse",
            "processors": "processors",
            "schedules": "schedules",
            "tasks": "tasks",
            "roles": "roles",
            "provider_groups": "provider-groups",
            "saml_config": "saml",
        }

        if not parts:
            return None

        base = parts[0]
        if base not in path_map:
            return None

        directory = path_map[base]

        # Handle nested resources
        if len(parts) > 2:
            # Check if second part is a sub-resource (not an action)
            actions = [
                "list",
                "create",
                "retrieve",
                "update",
                "delete",
                "revoke",
                "accept",
                "refresh",
                "switch",
                "report",
                "compliance",
                "threatscore",
                "latest",
                "metadata",
            ]

            if parts[1] not in actions:
                subdirectory = parts[1].replace("_", "-")
                action = "-".join(parts[2:])
                return f"{directory}/{subdirectory}/{action}.mdx"

        # Simple resource action
        action = "-".join(parts[1:])
        return f"{directory}/{action}.mdx"

    def format_title(self, operation_id: str, summary: Optional[str]) -> str:
        """Format title from operation ID or summary"""
        if summary:
            return summary

        parts = operation_id.split("_")
        action = parts[-1].replace("_", " ").title()
        resource = " ".join(parts[:-1]).replace("_", " ").title()
        return f"{action} {resource}"

    def extract_parameters(self, operation: Dict[str, Any]) -> str:
        """Extract and format parameters section"""
        parameters = operation.get("parameters", [])
        if not parameters:
            return ""

        path_params = [p for p in parameters if p.get("in") == "path"]
        query_params = [p for p in parameters if p.get("in") == "query"]

        sections = []

        if path_params:
            sections.append("## Path Parameters\n")
            for param in path_params:
                name = param.get("name")
                required = "required" if param.get("required") else "optional"
                desc = param.get("description", "No description")
                schema = param.get("schema", {})
                param_type = schema.get("type", "string")
                sections.append(f"- `{name}` ({required}, {param_type}) - {desc}")

        if query_params:
            sections.append("\n## Query Parameters\n")
            for param in query_params:
                name = param.get("name")
                required = "required" if param.get("required") else "optional"
                desc = param.get("description", "No description")
                schema = param.get("schema", {})
                param_type = schema.get("type", "string")
                sections.append(f"- `{name}` ({required}, {param_type}) - {desc}")

        return "\n".join(sections)

    def extract_request_body(self, operation: Dict[str, Any]) -> str:
        """Extract and format request body section"""
        request_body = operation.get("requestBody")
        if not request_body:
            return ""

        content = request_body.get("content", {})
        json_content = content.get("application/vnd.api+json", {})

        if not json_content:
            return ""

        example = json_content.get("example", {})

        if example:
            example_json = json.dumps(example, indent=2)
            return f"""
## Request Body

```json
{example_json}
```
"""

        # If no example, show schema info
        schema = json_content.get("schema", {})
        if schema:
            return """
## Request Body

Request body follows JSON:API specification. See OpenAPI spec for detailed schema.
"""

        return ""

    def extract_responses(self, operation: Dict[str, Any]) -> str:
        """Extract and format responses section"""
        responses = operation.get("responses", {})
        if not responses:
            return ""

        sections = []

        # Success response
        for status in ["200", "201", "204"]:
            response = responses.get(status)
            if response:
                desc = response.get("description", "Success")
                sections.append(f"## Response\n\n{desc}\n")

                content = response.get("content", {})
                json_content = content.get("application/vnd.api+json", {})
                example = json_content.get("example", {})

                if example:
                    example_json = json.dumps(example, indent=2)
                    sections.append(f"```json\n{example_json}\n```\n")

                break

        return "\n".join(sections)

    def generate_mdx(
        self, operation_id: str, method: str, path: str, operation: Dict[str, Any]
    ) -> str:
        """Generate complete MDX content for an endpoint"""

        title = self.format_title(operation_id, operation.get("summary"))
        description = operation.get("description") or operation.get("summary") or ""
        api_path = f"{method.upper()} {path}"

        # Extract sections
        parameters = self.extract_parameters(operation)
        request_body = self.extract_request_body(operation)
        responses = self.extract_responses(operation)

        # Build MDX content
        mdx_parts = [
            "---",
            f'title: "{title}"',
            f'api: "{api_path}"',
            f'description: "{description}"',
            "---",
            "",
            description,
            "",
        ]

        if parameters:
            mdx_parts.extend([parameters, ""])

        if request_body:
            mdx_parts.extend([request_body, ""])

        if responses:
            mdx_parts.extend([responses, ""])

        return "\n".join(mdx_parts).strip() + "\n"

    def generate_docs(self, update_existing: bool = False, dry_run: bool = False):
        """Generate MDX files for all operations"""

        if not self.spec:
            raise ValueError("OpenAPI spec not loaded. Call load_spec() first.")

        print("\n🔄 Generating documentation files...")
        print(f"   Update existing: {update_existing}")
        print(f"   Dry run: {dry_run}\n")

        generated_files = []
        skipped_files = []
        error_files = []

        paths = self.spec.get("paths", {})
        total_operations = sum(
            len([m for m in p.keys() if m in ["get", "post", "put", "patch", "delete"]])
            for p in paths.values()
        )

        print(f"Found {total_operations} operations to process\n")

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete"]:
                operation = path_item.get(method)
                if not operation:
                    continue

                operation_id = operation.get("operationId")
                if not operation_id:
                    continue

                try:
                    file_path = self.operation_id_to_path(operation_id)
                    if not file_path:
                        skipped_files.append((operation_id, "Could not determine path"))
                        self.stats["skipped"] += 1
                        continue

                    full_path = self.api_reference_dir / file_path

                    # Check if file exists and should be skipped
                    if full_path.exists() and not update_existing:
                        # Check if file has substantial content
                        if full_path.stat().st_size > 150:
                            skipped_files.append(
                                (operation_id, "File exists with content")
                            )
                            self.stats["skipped"] += 1
                            continue

                    # Generate MDX content
                    mdx_content = self.generate_mdx(
                        operation_id, method, path, operation
                    )

                    if dry_run:
                        print(f"Would generate: {file_path}")
                        generated_files.append(file_path)
                        continue

                    # Create directory if needed
                    full_path.parent.mkdir(parents=True, exist_ok=True)

                    # Write file
                    action = "Updated" if full_path.exists() else "Generated"
                    with open(full_path, "w") as f:
                        f.write(mdx_content)

                    generated_files.append(file_path)
                    if action == "Updated":
                        self.stats["updated"] += 1
                    else:
                        self.stats["generated"] += 1

                    print(f"✅ {action}: {file_path}")

                except Exception as e:
                    error_files.append((operation_id, str(e)))
                    self.stats["errors"] += 1
                    print(f"❌ Error processing {operation_id}: {e}")

        # Print summary
        print("\n" + "=" * 60)
        print("📊 Generation Summary")
        print("=" * 60)
        print(f"Generated: {self.stats['generated']}")
        print(f"Updated:   {self.stats['updated']}")
        print(f"Skipped:   {self.stats['skipped']}")
        print(f"Errors:    {self.stats['errors']}")
        print(f"Total:     {total_operations}")

        if skipped_files and len(skipped_files) <= 10:
            print("\nSkipped operations:")
            for op_id, reason in skipped_files:
                print(f"  - {op_id}: {reason}")

        if error_files:
            print("\nErrors:")
            for op_id, error in error_files:
                print(f"  - {op_id}: {error}")

        return self.stats


def main():
    parser = argparse.ArgumentParser(
        description="Generate Mintlify MDX documentation from OpenAPI spec"
    )
    parser.add_argument(
        "--update-existing", action="store_true", help="Update existing MDX files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be generated without writing files",
    )

    args = parser.parse_args()

    # Paths
    script_dir = Path(__file__).parent
    openapi_file = script_dir / "api-reference" / "openapi.yaml"
    api_reference_dir = script_dir / "api-reference"

    # Check if OpenAPI file exists
    if not openapi_file.exists():
        print(f"❌ Error: OpenAPI spec not found at {openapi_file}")
        print("   Run ./sync-api-spec.sh first to download the spec")
        sys.exit(1)

    # Generate documentation
    generator = APIDocGenerator(str(openapi_file), str(api_reference_dir))

    try:
        generator.load_spec()
        generator.generate_docs(
            update_existing=args.update_existing, dry_run=args.dry_run
        )

        if not args.dry_run:
            print("\n✅ Documentation generation complete!")
            print("\n💡 Next steps:")
            print("   1. Review generated files in api-reference/")
            print("   2. Add detailed descriptions and examples")
            print("   3. Update docs.json if new groups were added")
            print("   4. Test with: cd docs && mintlify dev")
        else:
            print("\n🔍 Dry run complete - no files were modified")

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
