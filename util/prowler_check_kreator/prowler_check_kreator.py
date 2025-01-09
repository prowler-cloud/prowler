#!/usr/bin/env python3
import json
import os
import sys

from util.prowler_check_kreator.lib.templates import (
    load_check_template,
    load_test_template,
)


class ProwlerCheckKreator:
    def __init__(self, provider: str, check_name: str):
        # Validate provider

        SUPPORTED_PROVIDERS = {"aws"}

        if provider in SUPPORTED_PROVIDERS:
            self._provider = provider
        else:
            raise ValueError(
                f"Invalid provider. Supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
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
            raise ValueError(
                f"Service {service_name} does not exist for {provider}. Please introduce a valid service"
            )

        # Ask user if want to use Gemini for all the process

        user_input = (
            input(
                "Do you want to use Gemini to create the check and metadata? Type 'yes'/'no' and press enter: "
            )
            .strip()
            .lower()
        )

        if user_input == "yes":
            # Let the user to use the model that he wants
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
                raise ValueError("Invalid model selected.")

            model_name = supported_models[model_index - 1]

            if "gemini" in model_name:
                from util.prowler_check_kreator.lib.llms.gemini import Gemini

                self._model = Gemini(model_name)

                # Provide some context about the check to create
                self._context = (
                    input(
                        "Please provide some context to generate the check and metadata:\n"
                    )
                ).strip()

            else:
                raise ValueError("Invalid model selected.")
        elif user_input == "no":
            self._model = None
            self._context = ""
        else:
            raise ValueError("Invalid input. Please type 'yes' or 'no'.")

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
                    f"Some files of {check_name} already exists. Do you want to continue and overwrite it? Type 'yes' if you want to continue: "
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
                raise ValueError(f"Check {check_name} already exists.")

    def kreate_check(self) -> None:
        """Create a new check in Prowler"""

        # Create the check
        print(f"Creating check {self._check_name} for {self._provider}")

        # Inside the check folder, create the check files: __init__.py, check_name.py, and check_name.metadata.json
        os.makedirs(self._check_path, exist_ok=True)

        with open(os.path.join(self._check_path, "__init__.py"), "w") as f:
            f.write("")

        self._write_check_file()
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

        self._write_test_file()

        print(f"Check {self._check_name} created successfully")

    def _check_exists(self, check_name: str) -> bool:
        """Ensure if any file related to the check already exists.

        Args:
            check_name: The name of the check.

        Returns:
            True if the check already exists, False otherwise.
        """

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

        # Check if exits check.py, check_metadata.json or check_test.py
        return (
            os.path.exists(check_path)
            or os.path.exists(os.path.join(check_path, "__init__.py"))
            or os.path.exists(os.path.join(check_path, f"{check_name}.py"))
            or os.path.exists(os.path.join(check_path, f"{check_name}.metadata.json"))
            or os.path.exists(_test_path)
        )

    def _write_check_file(self) -> None:
        """Write the check file"""

        if self._model is None:
            check_content = load_check_template(
                self._provider, self._service_name, self._check_name
            )
        else:
            check_content = self._model.generate_check(
                check_name=self._check_name, context=self._context
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

        if self._model is None:
            filled_metadata = metadata_template
        else:
            filled_metadata = self._model.generate_metadata(
                metadata_template, self._context
            )

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

        if self._model is None:
            test_template = load_test_template(
                self._provider, self._service_name, self._check_name
            )
        else:
            test_template = self._model.generate_test(self._check_name)

        with open(os.path.join(test_folder, f"{self._check_name}_test.py"), "w") as f:
            f.write(test_template)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError(
                "Invalid arguments. Usage: python prowler_check_kreator.py <cloud_provider> <check_name>"
            )

        prowler_check_creator = ProwlerCheckKreator(sys.argv[1], sys.argv[2])

        sys.exit(prowler_check_creator.kreate_check())

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
