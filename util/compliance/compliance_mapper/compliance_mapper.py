"""
Compliance Mapper CLI - Interactive tool for mapping compliance frameworks with Prowler Hub checks
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import requests

# Rich for beautiful CLI interface
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Installing rich for better CLI experience...")
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table

console = Console()


@dataclass
class ComplianceRequirement:
    id: str
    description: str
    attributes: Dict[str, Any]
    checks: List[str]
    additional: str


@dataclass
class ProwlerCheck:
    id: str
    title: str
    description: str
    provider: str
    service: str
    severity: str
    categories: List[str]
    code: str


class ComplianceMapper:
    def __init__(self):
        self.console = Console()
        self.compliance_data = None
        self.prowler_checks = {}
        self.available_fields = []
        self.selected_fields = []
        self.requirements = []
        self.results = []  # Store processing results
        self.openai_api_key = None

    def display_banner(self):
        """Display application banner"""
        banner = """
        ╔═══════════════════════════════════════════════════════════════╗
        ║                    🛡️  COMPLIANCE MAPPER CLI                   ║
        ║                                                               ║
        ║     Intelligent mapping of compliance frameworks              ║
        ║           with Prowler Hub security checks                    ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold blue")

    def load_compliance_file(self, file_path: str) -> bool:
        """Load and validate compliance framework JSON file"""
        try:
            path = Path(file_path)
            if not path.exists():
                self.console.print(f"❌ File not found: {file_path}", style="bold red")
                return False

            with open(path, "r", encoding="utf-8") as f:
                self.compliance_data = json.load(f)

            # Validate required fields
            required_fields = ["Framework", "Provider", "Requirements"]
            missing_fields = [
                field for field in required_fields if field not in self.compliance_data
            ]

            if missing_fields:
                self.console.print(
                    f"❌ Missing required fields: {', '.join(missing_fields)}",
                    style="bold red",
                )
                return False

            if not isinstance(self.compliance_data["Requirements"], list):
                self.console.print(
                    "❌ 'Requirements' must be an array", style="bold red"
                )
                return False

            # Display compliance info
            panel = Panel(
                f"📋 **Framework:** {self.compliance_data['Framework']}\n"
                f"🔧 **Provider:** {self.compliance_data['Provider']}\n"
                f"📊 **Version:** {self.compliance_data.get('Version', 'N/A')}\n"
                f"📝 **Requirements:** {len(self.compliance_data['Requirements'])}\n"
                f"💾 **File Size:** {path.stat().st_size / 1024:.1f} KB",
                title="✅ Compliance Framework Loaded",
                style="green",
            )
            self.console.print(panel)

            return True

        except json.JSONDecodeError as e:
            self.console.print(f"❌ Invalid JSON format: {e}", style="bold red")
            return False
        except Exception as e:
            self.console.print(f"❌ Error loading file: {e}", style="bold red")
            return False

    def analyze_json_structure(self) -> List[str]:
        """Analyze JSON structure to find available fields"""
        fields = set()
        requirements = self.compliance_data["Requirements"]

        # Analyze first 10 requirements to find available fields
        sample_requirements = requirements[: min(10, len(requirements))]

        for req in sample_requirements:
            # Main requirement fields
            for key, value in req.items():
                if isinstance(value, str) and len(value) > 10:
                    fields.add(key)

            # Nested fields in Attributes
            if "Attributes" in req and isinstance(req["Attributes"], list):
                for attr in req["Attributes"]:
                    if isinstance(attr, dict):
                        for key, value in attr.items():
                            if isinstance(value, str) and len(value) > 10:
                                fields.add(f"Attributes.{key}")

        return sorted(list(fields))

    def display_field_selection(self) -> bool:
        """Interactive field selection for search"""
        self.available_fields = self.analyze_json_structure()

        if not self.available_fields:
            self.console.print(
                "❌ No suitable fields found for analysis", style="bold red"
            )
            return False

        self.console.print("\n🔍 **Available fields for analysis:**\n")

        # Display fields with examples
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Index", style="cyan", width=8)
        table.add_column("Field Name", style="green")
        table.add_column("Sample Content", style="yellow")

        sample_req = self.compliance_data["Requirements"][0]

        for i, field in enumerate(self.available_fields, 1):
            sample_value = self.get_field_value(sample_req, field)
            truncated_sample = (
                (sample_value[:80] + "...") if len(sample_value) > 80 else sample_value
            )
            table.add_row(str(i), field, truncated_sample)

        self.console.print(table)

        # Interactive selection
        while True:
            selection = Prompt.ask(
                "\n🎯 Enter field numbers to use (comma-separated, e.g., 1,3,5)",
                default="1,2",
            )

            try:
                indices = [int(x.strip()) for x in selection.split(",")]
                if all(1 <= i <= len(self.available_fields) for i in indices):
                    self.selected_fields = [
                        self.available_fields[i - 1] for i in indices
                    ]
                    break
                else:
                    self.console.print(
                        "❌ Invalid indices. Please try again.", style="bold red"
                    )
            except ValueError:
                self.console.print(
                    "❌ Invalid format. Please enter numbers separated by commas.",
                    style="bold red",
                )

        # Confirm selection
        selected_display = ", ".join(self.selected_fields)
        panel = Panel(
            f"Selected fields: **{selected_display}**",
            title="✅ Field Selection Complete",
            style="green",
        )
        self.console.print(panel)

        return True

    def get_field_value(self, requirement: Dict, field_path: str) -> str:
        """Extract field value from requirement using dot notation"""
        if field_path.startswith("Attributes."):
            field_name = field_path.replace("Attributes.", "")
            if "Attributes" in requirement and isinstance(
                requirement["Attributes"], list
            ):
                if len(requirement["Attributes"]) > 0:
                    return requirement["Attributes"][0].get(field_name, "")
            return ""
        return requirement.get(field_path, "")

    def load_prowler_checks(self) -> bool:
        """Load all checks from Prowler Hub API"""
        provider = self.compliance_data["Provider"].lower()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                f"🔄 Loading ALL {provider.upper()} checks from Prowler Hub...",
                total=None,
            )

            try:
                # Try direct API call
                url = f"https://hub.prowler.com/api/check?providers={provider}"
                response = requests.get(url, timeout=30)

                if response.status_code == 200:
                    checks_data = response.json()

                    if isinstance(checks_data, list) and len(checks_data) > 0:

                        for check in checks_data:
                            self.prowler_checks[check["id"]] = ProwlerCheck(
                                id=check.get("id", ""),
                                title=check.get("title", ""),
                                description=check.get("description", ""),
                                provider=check.get("provider", ""),
                                service=check.get("service", ""),
                                severity=check.get("severity", ""),
                                categories=check.get("categories", []),
                                code=None,
                            )

                        progress.update(task, completed=True)

                        # Display success info
                        panel = Panel(
                            f"🎉 **Successfully loaded {len(self.prowler_checks.keys())} checks**\n\n"
                            f"Provider: {provider.upper()}\n"
                            f"Services covered: {len(set(check.service for check in self.prowler_checks.values()))}\n"
                            f"Severity levels: {', '.join(set(check.severity for check in self.prowler_checks.values()))}",
                            title="✅ Prowler Hub Connection Successful",
                            style="green",
                        )
                        self.console.print(panel)
                        return True
                    else:
                        raise Exception("No checks found")

                # API call failed
                raise Exception(f"API returned status {response.status_code}")

            except Exception as e:
                progress.update(task, completed=True)
                self.console.print(
                    f"\n❌ Failed to connect to Prowler Hub: {e}", style="bold red"
                )
                return False

    def add_check_code(self) -> bool:
        """Add check code from GitHub"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                "🔄 Getting check code from GitHub...",
                total=len(self.prowler_checks.keys()),
            )
            try:
                # Use concurrent processing for faster execution
                with ThreadPoolExecutor(max_workers=10) as executor:
                    # Create futures for all check code requests
                    futures = {
                        executor.submit(
                            self.get_check_code,
                            self.compliance_data["Provider"].lower(),
                            self.prowler_checks[check_id].service,
                            check_id,
                        ): check_id
                        for check_id in self.prowler_checks.keys()
                    }

                    # Process completed futures
                    for future in as_completed(futures):
                        check_id = futures[future]
                        try:
                            code = future.result()
                            self.prowler_checks[check_id].code = code
                        except Exception as e:
                            self.console.print(
                                f"❌ Error getting code for {check_id}: {e}",
                                style="red",
                            )
                            self.prowler_checks[check_id].code = ""

                        progress.update(task, advance=1)

                # Display success info
                panel = Panel(
                    f"🎉 **Successfully added check code for {len(self.prowler_checks.keys())} checks**",
                    title="✅ Check Code from GitHub Added",
                    style="green",
                )
                self.console.print(panel)
                progress.update(task, completed=True)

                return True
            except Exception as e:
                self.console.print(
                    f"❌ Failed to get check code from GitHub: {e}", style="bold red"
                )
                return False

    def get_check_code(self, provider, service, check_id) -> str:
        """Get the check code from GitHub"""
        try:
            check_code_url = f"https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/providers/{provider}/services/{service}/{check_id}/{check_id}.py"
            response_code = requests.get(check_code_url)

            return response_code.text
        except Exception as e:
            self.console.print(
                f"❌ Failed to get check code from GitHub: {e}", style="bold red"
            )
            return None

    def validate_openai_api_key(self) -> bool:
        """Validate OpenAI API key with a simple test request"""
        if not self.openai_api_key:
            return False

        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}",
            }

            # Simple test request with GPT-5
            payload = {
                "model": "gpt-5-nano",
                "messages": [{"role": "user", "content": "Hi"}],
                "max_completion_tokens": 10,
            }

            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=10,
            )

            if response.status_code == 200:
                self.console.print(
                    "✅ OpenAI API key validated successfully", style="green"
                )
                return True
            elif response.status_code == 401:
                self.console.print("❌ Invalid OpenAI API key", style="bold red")
                return False
            elif response.status_code == 400:
                # Check if it's a model issue
                error_data = response.json() if response.content else {}
                if "model" in str(error_data) or "gpt-5-nano" in str(error_data):
                    self.console.print(
                        "⚠️ GPT-5 model not available yet, but API key seems valid. Proceeding...",
                        style="yellow",
                    )
                    return True
                else:
                    self.console.print(
                        f"⚠️ API validation failed with 400: {error_data}",
                        style="yellow",
                    )
                    return False
            elif response.status_code == 404:
                self.console.print(
                    "⚠️ GPT-5 model not found. API key valid but model unavailable. Proceeding...",
                    style="yellow",
                )
                return True
            else:
                self.console.print(
                    f"⚠️ API validation returned status {response.status_code}",
                    style="yellow",
                )
                # For other status codes, assume API key might be valid
                return True

        except Exception as e:
            self.console.print(f"⚠️ API validation failed: {e}", style="yellow")
            # If validation fails due to network issues, assume key might be valid
            return True

    def setup_openai_api(self) -> bool:
        """Setup and validate OpenAI API key"""
        while True:
            if os.getenv("OPENAI_API_KEY"):
                self.openai_api_key = os.getenv("OPENAI_API_KEY")
                return True
            if not self.openai_api_key:
                self.console.print("\n🤖 **AI Analysis Setup**", style="bold cyan")
                self.console.print("To use AI analysis, you need an OpenAI API key.")
                self.console.print(
                    "Get one at: https://platform.openai.com/api-keys", style="blue"
                )

                self.openai_api_key = Prompt.ask(
                    "🔑 Enter your OpenAI API key (or 'skip' to skip AI analysis)",
                    password=True,
                )

                if self.openai_api_key.lower() == "skip":
                    self.console.print("⚠️ Skipping AI analysis.", style="yellow")
                    self.openai_api_key = None
                    return False

            # Try validation, but be tolerant of validation issues
            validation_result = self.validate_openai_api_key()

            if validation_result:
                return True
            else:
                # Even if validation fails, ask user if they want to proceed
                self.console.print("⚠️ API key validation had issues.", style="yellow")

                if Confirm.ask(
                    "🤔 Do you want to proceed anyway? (The key might still work for analysis)"
                ):
                    self.console.print(
                        "✅ Proceeding with AI analysis...", style="green"
                    )
                    return True
                else:
                    self.openai_api_key = None
                    if not Confirm.ask("🔄 Would you like to try a different API key?"):
                        self.console.print("⚠️ Skipping AI analysis.", style="yellow")
                        return False

    def ask_for_additional_field(self) -> bool:
        """Ask user if they want to include the Additional field in the output"""
        self.console.print("\n📝 **Output Configuration**", style="bold cyan")
        self.console.print(
            "The 'Additional' field contains AI-generated justifications for each mapping."
        )
        self.console.print(
            "This can be useful for understanding why specific checks were selected."
        )

        include_additional = Confirm.ask(
            "🤔 Do you want to include the 'Additional' field in the output?"
        )

        if include_additional:
            self.console.print(
                "✅ Additional field will be included in the output", style="green"
            )
        else:
            self.console.print("⚠️ Additional field will be skipped", style="yellow")

        return include_additional

    def analyze_with_ai(
        self,
        requirement: Dict,
        prowler_checks: Dict[str, ProwlerCheck],
        include_additional: bool = True,
    ) -> Dict[str, Any]:
        """Use OpenAI GPT-5 to analyze requirement and select most relevant checks"""
        if not prowler_checks:
            return {
                "relevant_checks": [],
                "justification": (
                    "No relevant checks found for this requirement"
                    if include_additional
                    else ""
                ),
            }

        # Build context from selected fields
        context_parts = []
        for field in self.selected_fields:
            value = self.get_field_value(requirement, field)
            if value:
                context_parts.append(f"{field}: {value}")

        requirement_context = "\n".join(context_parts)
        try:
            # Format checks for AI analysis
            checks_text = "\n\n".join(
                [
                    f"ID: {check.id}\n"
                    f"Title: {check.title}\n"
                    f"Service: {check.service}\n"
                    f"Severity: {check.severity}\n"
                    f"Categories: {', '.join(check.categories)}\n"
                    f"Description: {check.description}\n"
                    f"Code: {check.code}\n"
                    for check in prowler_checks.values()
                ]
            )
        except Exception as e:
            self.console.print(
                f"❌ Error formatting checks for AI analysis: {e}", style="bold red"
            )
            return {
                "relevant_checks": [],
                "justification": (
                    "there is an error in the check code" if include_additional else ""
                ),
            }

        # Adjust prompt based on whether additional field is needed
        if include_additional:
            prompt = f"""You are a cybersecurity compliance expert. Analyze this requirement against security checks.

COMPLIANCE REQUIREMENT:
ID: {requirement.get('Id', 'N/A')}
{requirement_context}

SECURITY CHECKS ({len(prowler_checks.keys())} checks with the metadata and code):
{checks_text}

Your task:
1. From these {len(prowler_checks.keys())} check with the metadata and code, select only those that are closely related to the requirement taking into account the code and metadata.
2. Consider the technical controls, security concepts, and implementation details mentioned
3. Ensure the checks can actually be used to demonstrate compliance with this requirement
4. Provide specific justification linking each selected check to the requirement

Respond ONLY with valid JSON:
{{
  "relevant_checks": ["check_id1", "check_id2"],
  "justification": "Detailed explanation of how each selected check directly addresses the compliance requirement, including specific technical controls and validation mechanisms."
}}

If none of the checks directly validate this requirement:
{{
  "relevant_checks": [],
  "justification": "While {len(prowler_checks.keys())} checks were found through search, none directly validate the specific compliance controls required by this requirement."
}}

NO TEXT OUTSIDE JSON."""
        else:
            prompt = f"""You are a cybersecurity compliance expert. Analyze this requirement against security checks.

COMPLIANCE REQUIREMENT:
ID: {requirement.get('Id', 'N/A')}
{requirement_context}

SECURITY CHECKS ({len(prowler_checks.keys())} checks with the metadata and code):
{checks_text}

Your task:
1. From these {len(prowler_checks.keys())} check with the metadata and code, select only those that are closely related to the requirement taking into account the code and metadata.
2. Consider the technical controls, security concepts, and implementation details mentioned
3. Ensure the checks can actually be used to demonstrate compliance with this requirement

Respond ONLY with valid JSON:
{{
  "relevant_checks": ["check_id1", "check_id2"]
}}

If none of the checks directly validate this requirement:
{{
  "relevant_checks": []
}}

NO TEXT OUTSIDE JSON."""

        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}",
            }

            payload = {
                "model": "gpt-5-nano",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 1,  # Low temperature for consistent results
                "response_format": {"type": "json_object"},  # Force JSON response
            }

            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
            )

            if response.status_code == 200:
                data = response.json()
                response_text = data["choices"][0]["message"]["content"].strip()

                try:
                    result = json.loads(response_text)
                except json.JSONDecodeError:
                    # If JSON parsing fails, try to extract JSON from the response
                    import re

                    json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group())
                    else:
                        raise Exception("Could not parse JSON from AI response")

                # Validate that suggested checks exist in our dataset
                valid_checks = [
                    check_id
                    for check_id in result.get("relevant_checks", [])
                    if check_id in prowler_checks.keys()
                ]

                return {
                    "relevant_checks": valid_checks,
                    "justification": result.get(
                        "justification", "No justification provided"
                    ),
                }

            elif response.status_code == 400:
                error_details = (
                    response.json() if response.content else {"error": "Unknown error"}
                )
                self.console.print(
                    f"❌ OpenAI API Error (400): {error_details}", style="bold red"
                )

                raise Exception(f"API request failed: {error_details}")

            elif response.status_code == 401:
                self.console.print(
                    "❌ Authentication failed. Please check your OpenAI API key.",
                    style="bold red",
                )
                self.openai_api_key = None
                raise Exception("Authentication failed")

            elif response.status_code == 429:
                self.console.print(
                    "⏳ Rate limit exceeded. Waiting 30 seconds...", style="yellow"
                )
                time.sleep(30)
                return self.analyze_with_ai(requirement, prowler_checks)

            else:
                raise Exception(
                    f"API request failed with status {response.status_code}: {response.text}"
                )

        except requests.exceptions.Timeout:
            self.console.print("⏳ Request timed out. Retrying...", style="yellow")
            return self.analyze_with_ai(requirement, prowler_checks)

        except requests.exceptions.ConnectionError:
            self.console.print(
                "🌐 Connection error. Check your internet connection.", style="yellow"
            )
            return self.analyze_with_ai(requirement, prowler_checks)

        except Exception as e:
            self.console.print(f"⚠️ AI analysis failed: {e}", style="yellow")

    def process_all_requirements(self, include_additional: bool = True) -> bool:
        """Process all requirements with search + AI analysis"""
        requirements = self.compliance_data["Requirements"]
        results = []

        # Setup AI analysis
        self.setup_openai_api()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:

            task = progress.add_task(
                "🧠 Processing requirements...", total=len(requirements)
            )

            for i, requirement in enumerate(requirements):
                progress.update(
                    task,
                    description=f"🧠 Processing requirement {i + 1}/{len(requirements)}: {requirement.get('Id', 'Unknown')}",
                )

                ai_result = self.analyze_with_ai(
                    requirement, self.prowler_checks, include_additional
                )

                results.append(
                    {
                        "requirement_id": requirement.get("Id", f"req_{i}"),
                        "suggested_checks": ai_result["relevant_checks"],
                        "justification": ai_result.get("justification", ""),
                        "original_requirement": requirement,
                        "search_matches": len(self.prowler_checks.keys()),
                    }
                )

                progress.update(task, advance=1)
                time.sleep(1)  # 1 second delay between AI requests

        self.results = results

        # Display summary
        total_mapped = sum(1 for r in results if len(r["suggested_checks"]) > 0)
        total_checks_assigned = sum(len(r["suggested_checks"]) for r in results)

        analysis_method = "AI"

        panel = Panel(
            f"📊 **Processing Complete!**\n\n"
            f"Analysis Method: {analysis_method}\n"
            f"Total Requirements: {len(requirements)}\n"
            f"Successfully Mapped: {total_mapped}\n"
            f"Mapping Percentage: {(total_mapped / len(requirements) * 100):.1f}%\n"
            f"Total Checks Assigned: {total_checks_assigned}\n"
            f"Average Checks per Requirement: {(total_checks_assigned / len(requirements)):.1f}\n"
            f"Additional Field: {'Included' if include_additional else 'Skipped'}",
            title="✅ Analysis Complete",
            style="green",
        )
        self.console.print(panel)

        return True

    def generate_output_file(
        self, output_path: str, include_additional: bool = True
    ) -> bool:
        """Generate final compliance file with mapped checks"""
        try:
            # Create a copy of original compliance data
            final_compliance = self.compliance_data.copy()

            # Update requirements with mapped checks
            for i, requirement in enumerate(final_compliance["Requirements"]):
                if i < len(self.results):
                    result = self.results[i]

                    # Update Checks field
                    requirement["Checks"] = result["suggested_checks"]

                    # Update Attributes.Additional field only if requested
                    if include_additional:
                        if "Attributes" not in requirement:
                            requirement["Attributes"] = [{}]
                        elif not isinstance(requirement["Attributes"], list):
                            requirement["Attributes"] = [{}]
                        elif len(requirement["Attributes"]) == 0:
                            requirement["Attributes"] = [{}]

                        for attr in requirement["Attributes"]:
                            attr["Additional"] = result["justification"]

            # Write to output file
            output_path_obj = Path(output_path)
            with open(output_path_obj, "w", encoding="utf-8") as f:
                json.dump(final_compliance, f, indent=2, ensure_ascii=False)

            # Display success message
            fields_updated = ["Checks"]
            if include_additional:
                fields_updated.append("Attributes.Additional")

            panel = Panel(
                f"📁 **Output file created successfully!**\n\n"
                f"File: {output_path}\n"
                f"Size: {output_path_obj.stat().st_size / 1024:.1f} KB\n"
                f"Requirements processed: {len(self.results)}\n"
                f"Fields updated: {', '.join(fields_updated)}",
                title="✅ File Generation Complete",
                style="green",
            )
            self.console.print(panel)

            return True

        except Exception as e:
            self.console.print(
                f"❌ Error generating output file: {e}", style="bold red"
            )
            return False

    def run_interactive(self):
        """Run the interactive CLI workflow"""
        self.display_banner()

        # Step 1: Load compliance file
        while True:
            file_path = Prompt.ask("📁 Enter path to compliance framework JSON file")
            if self.load_compliance_file(file_path):
                break

        # Step 2: Field selection
        if not self.display_field_selection():
            return

        # Step 3: Load Prowler checks
        if not self.load_prowler_checks():
            return

        # Step 4: Add check code
        if not self.add_check_code():
            return

        # Step 5: Process all requirements
        include_additional = self.ask_for_additional_field()
        if not self.process_all_requirements(include_additional):
            return

        # Step 6: Generate output file
        default_output = f"{Path(file_path).stem}_mapped.json"
        output_path = Prompt.ask("💾 Enter output file path", default=default_output)

        if self.generate_output_file(output_path, include_additional):
            self.console.print(
                "\n🎉 **Compliance mapping completed successfully!**",
                style="bold green",
            )
        else:
            self.console.print(
                "\n❌ **Failed to generate output file**", style="bold red"
            )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Compliance Mapper CLI - Interactive compliance framework mapping"
    )
    parser.add_argument("--file", "-f", help="Path to compliance framework JSON file")
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()

    mapper = ComplianceMapper()

    if args.file:
        # Non-interactive mode (partial)
        if mapper.load_compliance_file(args.file):
            mapper.console.print(
                "File loaded successfully. Use interactive mode for full processing.",
                style="green",
            )
    else:
        # Interactive mode
        try:
            mapper.run_interactive()
        except KeyboardInterrupt:
            mapper.console.print("\n\n👋 Operation cancelled by user.", style="yellow")
        except Exception as e:
            mapper.console.print(f"\n❌ Unexpected error: {e}", style="bold red")
            import traceback

            mapper.console.print(
                f"Debug info: {traceback.format_exc()}", style="dim red"
            )


if __name__ == "__main__":
    main()
