#!/usr/bin/env python3
import json
import os
import sys

import google.generativeai as genai

from util.prowler_check_kreator.lib.metadata_types import (
    get_metadata_valid_check_type,
    get_metadata_valid_resource_type,
)
from util.prowler_check_kreator.lib.templates import (
    load_check_template,
    load_test_template,
)


# TODO: Support azure, gcp and kubernetes providers (only need to add check template, test template and metadata types)
# TODO: Add support for other LLMs like OpenAI's GPT or Ollama locally
# TODO: Add support to make configurable checks
# TODO: Improve the check generation with more context
class ProwlerCheckKreator:
    def __init__(self, provider: str, check_name: str):
        # Validate provider

        supported_providers = {"aws"}

        if provider in supported_providers:
            self._provider = provider
        else:
            raise ValueError(
                f"Invalid provider. Supported providers: {', '.join(supported_providers)}"
            )

        # Find the Prowler folder
        self._prowler_folder = os.path.abspath(
            os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
        )

        # Validate if service exists for the selected provider
        service_name = check_name.split("_")[0]

        service_path = os.path.join(
            self._prowler_folder,
            "prowler/providers/",
            provider,
            "services/",
            service_name,
        )

        if os.path.exists(service_path):
            self._service_name = service_name
        else:
            raise ValueError(f"Service {service_name} does not exist for {provider}")

        if not self._check_exists(check_name):
            self._check_name = check_name
            self._check_path = os.path.join(
                self._prowler_folder,
                "prowler/providers/",
                provider,
                "services/",
                service_name,
                check_name,
            )
        else:
            # Check already exists, give the user the possibility to continue or not
            user_input = (
                input(
                    f"Check {check_name} already exists. Do you want to continue and overwrite it? Type 'yes'/'no' and press enter: "
                )
                .strip()
                .lower()
            )

            if user_input == "no":
                raise ValueError(f"Check {check_name} already exists")
            else:
                self._check_name = check_name
                self._check_path = os.path.join(
                    self._prowler_folder,
                    "prowler/providers/",
                    provider,
                    "services/",
                    service_name,
                    check_name,
                )

    def kreate_check(self) -> None:
        """Create a new check in Prowler"""

        # Create the check
        print(f"Creating check {self._check_name} for {self._provider}")

        # Inside the check folder, create the check files: __init__.py, check_name.py, and check_name.metadata.json
        os.makedirs(self._check_path, exist_ok=True)

        with open(os.path.join(self._check_path, "__init__.py"), "w") as f:
            f.write("")

        # Check first if the check file already exists, in that case, ask user if want to overwrite it
        if os.path.exists(os.path.join(self._check_path, f"{self._check_name}.py")):
            user_input = (
                input(
                    f"Python check file {self._check_name} already exists. Do you want to overwrite it? Type 'yes'/'no' and press enter: "
                )
                .strip()
                .lower()
            )

            if user_input == "yes":
                self._write_check_file()
            else:
                print("Check file not overwritten")
        else:
            self._write_check_file()

        # Check if metadata file already exists, in that case, ask user if want to overwrite it
        if os.path.exists(
            os.path.join(self._check_path, f"{self._check_name}.metadata.json")
        ):
            user_input = (
                input(
                    f"Metadata file {self._check_name}.metadata.json already exists. Do you want to overwrite it? Type 'yes'/'no' and press enter: "
                )
                .strip()
                .lower()
            )
            if user_input == "yes":
                self._write_metadata_file()
            else:
                print("Metadata file not overwritten")
        else:
            self._write_metadata_file()

        # Create test directory if it does not exist
        test_folder = os.path.join(
            self._prowler_folder,
            "tests/providers/",
            self._provider,
            "services/",
            self._service_name,
            self._check_name,
        )

        os.makedirs(test_folder, exist_ok=True)

        # Check if test file already exists, in that case, ask user if want to overwrite it
        if os.path.exists(os.path.join(test_folder, f"{self._check_name}_test.py")):
            user_input = (
                input(
                    f"Python test file {self._check_name}_test.py already exists. Do you want to overwrite it? Type 'yes'/'no' and press enter: "
                )
                .strip()
                .lower()
            )

            if user_input == "yes":
                self._write_test_file()
            else:
                print("Test file not overwritten")
        else:
            self._write_test_file()

        print(f"Check {self._check_name} created successfully")

    def _check_exists(self, check_name: str) -> bool:
        """Check if the check already exists"""

        # Get the check path
        check_path = os.path.join(
            self._prowler_folder,
            "prowler/providers/",
            self._provider,
            "services/",
            self._service_name,
            check_name,
        )

        # Get the test path
        _test_path = os.path.join(
            self._prowler_folder,
            "tests/providers/",
            self._provider,
            "services/",
            self._service_name,
            check_name,
        )

        # Check if exits check.py, check_metadata.json and check_test.py
        return (
            os.path.exists(check_path)
            and os.path.exists(os.path.join(check_path, "__init__.py"))
            and os.path.exists(os.path.join(check_path, f"{check_name}.py"))
            and os.path.exists(os.path.join(check_path, f"{check_name}.metadata.json"))
            and os.path.exists(_test_path)
        )

    def _write_check_file(self) -> None:
        """Write the check file"""

        check_template = load_check_template(
            self._provider, self._service_name, self._check_name
        )

        # Ask if want that Gemini to fill the check taking as reference another check

        user_input = (
            input(
                "WARNING: This still in beta. The check generated may not have sense or you will have to add some parameters to the service\nDo you want to ask Gemini to fill the check now? If yes, type the reference check name and press enter. If not, press enter: "
            )
            .strip()
            .lower()
        )

        if user_input and self._check_exists(user_input):
            # Load the file referenced by the user
            with open(
                os.path.join(
                    self._prowler_folder,
                    "prowler/providers/",
                    self._provider,
                    "services/",
                    self._service_name,
                    user_input,
                    f"{user_input}.py",
                ),
                "r",
            ) as f:
                check_reference = f.read()

            check_template = self._fill_check_with_gemini(
                self._check_name, check_reference
            )
        else:
            print(
                "Referenced check does not exist. Check will be created with the standard template"
            )

        with open(os.path.join(self._check_path, f"{self._check_name}.py"), "w") as f:
            f.write(check_template)

    def _write_metadata_file(self) -> None:
        """Write the metadata file"""

        metadata_template = {
            "Provider": self._provider,
            "CheckID": self._check_name,
            "CheckTitle": "",
            "CheckType": [],
            "ServiceName": self._service_name,
            "SubServiceName": "",
            "ResourceIdTemplate": "",
            "Severity": "<critical, high, medium or low>",
            "ResourceType": "",
            "Description": "",
            "Risk": "",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {"Text": "", "Url": ""},
            },
            "Categories": [],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "",
        }

        # Ask if want that Gemini to fill the metadata

        user_input = (
            input(
                "Do you want to ask Gemini to fill the metadata now? Type 'yes'/'no' and press enter: "
            )
            .strip()
            .lower()
        )

        if user_input == "yes":
            # Ask for some context to fill the metadata

            context_sources = {"TrendMicro": "", "SecurityHub": "", "Other": ""}

            for source in context_sources:
                context_sources[source] = input(
                    f"Please provide some context from {source} (leave empty if none): "
                )

            filled_metadata = self._fill_metadata_with_gemini(
                metadata_template, context_sources
            )
        else:
            filled_metadata = metadata_template

        with open(
            os.path.join(self._check_path, f"{self._check_name}.metadata.json"), "w"
        ) as f:
            f.write(json.dumps(filled_metadata, indent=2))

    def _write_test_file(self) -> None:
        """Write the test file"""

        test_folder = os.path.join(
            self._prowler_folder,
            "tests/providers/",
            self._provider,
            "services/",
            self._service_name,
            self._check_name,
        )

        test_template = load_test_template(
            self._provider, self._service_name, self._check_name
        )

        with open(os.path.join(test_folder, f"{self._check_name}_test.py"), "w") as f:
            f.write(test_template)

    def _fill_check_with_gemini(self, check_name: str, check_reference: str) -> str:
        """Fill the check with Gemini AI

        Keyword arguments:
        check_name -- The name of the check to be created
        check_reference -- The reference check to be used as inspiration
        """

        filled_check = ""

        if check_reference:
            try:
                genai.configure(api_key=os.environ["GEMINI_API_KEY"])

                generation_config = {
                    "temperature": 0,
                    "top_p": 1,
                    "top_k": 1,
                }

                safety_settings = [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                ]

                model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    generation_config=generation_config,
                    safety_settings=safety_settings,
                )

                # Extract the class name from the reference check. Example: class elb_connection_draining_enabled(Check)
                class_name = check_reference.split("(")[0].split("class ")[1]

                prompt_parts = [
                    f"Your task is to create a new security check called '{check_name}' for Prowler (an open-source CSPM tool). The control is a Python class that inherits from the Check class and has only one method called execute. The execute method must return a list of Check_Report_AWS objects.",
                    "I need the answer only with Python formatted text.",
                    "Use the following check as inspiration to create the new check: ",
                    f"{class_name}:",
                    check_reference,
                    f"{check_name}:",
                ]

                response = model.generate_content(prompt_parts)

                if response:
                    # Format the response to a Python class, removing the prompt parts
                    filled_check = (
                        response.text.replace("python", "").replace("```", "").strip()
                    )

                else:
                    raise Exception("Error generating check with Gemini AI")

            except Exception as e:
                raise Exception(f"Error generating check with Gemini AI: {e}")

        return filled_check

    def _fill_metadata_with_gemini(self, metadata: dict, context_sources: dict) -> dict:
        filled_metadata = {}

        if metadata:
            try:
                genai.configure(api_key=os.environ["GEMINI_API_KEY"])

                generation_config = {
                    "temperature": 0,
                    "top_p": 1,
                    "top_k": 1,
                }

                safety_settings = [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                ]

                # Remove empty context sources
                context_sources = {k: v for k, v in context_sources.items() if v}

                # Remove metadata that we don't want to be filled by Gemini
                metadata.pop("SubServiceName", None)
                metadata["Remediation"]["Code"].pop("NativeIaC", None)
                metadata["Remediation"]["Code"].pop("Other", None)
                metadata["Remediation"]["Code"].pop("Terraform", None)
                metadata.pop("DependsOn", None)
                metadata.pop("RelatedTo", None)

                model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    generation_config=generation_config,
                    safety_settings=safety_settings,
                )

                prompt_parts = [
                    "Your task is to fill the metadata for a new cybersecurity check in Prowler (an open-source CSPM tool). The metadata is a JSON object with the following fields: ",
                    json.dumps(metadata, indent=2),
                    "Use the following context sources as inspiration to fill the metadata: ",
                    json.dumps(context_sources, indent=2),
                    "The field CheckType should be filled following the format: 'namespace/category/classifier', where namespace, category, and classifier are the values from the following dict: ",
                    json.dumps(
                        get_metadata_valid_check_type(metadata["Provider"]), indent=2
                    ),
                    "One example of a valid CheckType value is: 'Software and Configuration Checks/Vulnerabilities/CVE'. If you don't have a valid value for CheckType, you can leave it empty.",
                    "The field ResourceType must be one of the following values:",
                    ", ".join(get_metadata_valid_resource_type(metadata["Provider"])),
                    "If you don't have a valid value for ResourceType, you can leave it empty.",
                    "The field Category must be one or more of the following values: encryption, forensics-ready, internet-exposed, logging, redundancy, secrets, thread-detection, trustboundaries or vulnerability-management. If you don't have a valid value for Category, you can leave it empty.",
                    "I need the answer only with JSON formatted text.",
                ]

                response = model.generate_content(prompt_parts)

                if response:
                    # Format the response to a JSON object, removing the prompt parts
                    response = (
                        response.text.replace("\n", "")
                        .replace("json", "")
                        .replace("JSON", "")
                        .replace("```", "")
                        .strip()
                    )

                    filled_metadata = json.loads(response)

                    # Add removed fields back to the metadata
                    metadata["SubServiceName"] = ""
                    metadata["Remediation"]["Code"]["NativeIaC"] = ""
                    metadata["Remediation"]["Code"]["Other"] = ""
                    metadata["Remediation"]["Code"]["Terraform"] = ""
                    metadata["DependsOn"] = []
                    metadata["RelatedTo"] = []

                else:
                    raise Exception("Error generating metadata with Gemini AI")

            except Exception as e:
                raise Exception(f"Error generating metadata with Gemini AI: {e}")

        return filled_metadata


if __name__ == "__main__":
    try:
        if len(sys.argv) < 3:
            raise ValueError(
                "Invalid arguments. Usage: python prowler_check_kreator.py <cloud_provider> <check_name>"
            )

        prowler_check_creator = ProwlerCheckKreator(sys.argv[1], sys.argv[2])

        sys.exit(prowler_check_creator.kreate_check())

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
