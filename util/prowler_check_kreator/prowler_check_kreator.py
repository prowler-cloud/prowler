#!/usr/bin/env python3
import json
import os
import sys

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

            if user_input == "yes":
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
                raise ValueError(f"Check {check_name} already exists")

        # Let the user to use the model that he wants
        self._model = None
        supported_models = [
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-1.0-pro",
        ]

        print("Select the model that you want to use:")
        for i, model in enumerate(supported_models):
            print(f"{i + 1}. {model}")

        user_input = input(
            "Type the number of the model and press enter (default is 1): "
        ).strip()

        if not user_input:
            model_index = 1
        else:
            model_index = int(user_input)

        if model_index < 1 or model_index > len(supported_models):
            raise ValueError("Invalid model selected")

        model_name = supported_models[model_index - 1]

        if "gemini" in model_name:
            from util.prowler_check_kreator.lib.llms.gemini import Gemini

            self._model = Gemini(model_name)
        else:
            raise ValueError("Invalid model selected")

        self._check_reference_name = ""

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

        check_content = load_check_template(
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
            self._check_reference_name = user_input
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

            check_content = self._model.generate_check(
                self._check_name, check_reference
            )
        else:
            print(
                "Referenced check does not exist. Check will be created with the standard template."
            )

        with open(os.path.join(self._check_path, f"{self._check_name}.py"), "w") as f:
            f.write(check_content)

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

        if user_input.lower().strip() == "yes":
            # Ask for some context to the user to generate the metadata, the context input finishes with a blank line

            print(
                "Please provide some context to fill the metadata (end with an empty line):"
            )
            context_lines = []
            while True:
                line = input()
                if line:
                    context_lines.append(line)
                else:
                    break
            context = "\n".join(context_lines)

            filled_metadata = self._model.generate_metadata(metadata_template, context)
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

        test_content = load_test_template(
            self._provider, self._service_name, self._check_name
        )

        # Ask if want that Gemini to fill the test taking as reference the other check tests
        if self._check_reference_name:
            user_input = (
                input(
                    "Do you want to ask Gemini to fill the test now (based on check provided as reference in the check creation)? Type 'yes'/'no' and press enter: "
                )
                .strip()
                .lower()
            )

            if user_input.lower().strip() == "yes":
                # Load the file referenced by the user
                with open(
                    os.path.join(
                        self._prowler_folder,
                        "tests/providers/",
                        self._provider,
                        "services/",
                        self._service_name,
                        self._check_reference_name,
                        f"{self._check_reference_name}_test.py",
                    ),
                    "r",
                ) as f:
                    test_content = f.read()

                test_template = self._model.generate_test(
                    self._check_name, test_content
                )

        with open(os.path.join(test_folder, f"{self._check_name}_test.py"), "w") as f:
            f.write(test_template)


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
