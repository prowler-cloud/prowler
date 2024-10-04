import json
import os
import re

import google.generativeai as genai

from util.prowler_check_kreator.lib.metadata_types import (
    get_metadata_valid_check_type,
    get_metadata_valid_resource_type,
)


class Gemini:
    def __init__(self, model: str = "gemini-1.5-flash"):
        if os.getenv("GEMINI_API_KEY"):
            self.api_key = os.getenv("GEMINI_API_KEY")
        else:
            raise Exception("GEMINI_API_KEY environment variable is not set")

        if model not in ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]:
            raise Exception("Invalid Gemini AI model")

        self.model_name = model
        self.generation_config = {
            "temperature": 0,
            "top_p": 1,
            "top_k": 1,
        }
        self.safety_settings = [
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
        self._configure_genai()

    def _configure_genai(self):
        """Configure the Gemini AI model."""
        try:
            genai.configure(api_key=self.api_key)
        except Exception as e:
            raise Exception(f"Error configuring Gemini AI: {e}")

    def _generate_content(self, prompt_parts: list) -> str:
        """Generate content using Gemini AI based on provided prompts."""
        try:
            model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=self.generation_config,
                safety_settings=self.safety_settings,
            )
            response = model.generate_content(prompt_parts)
            if response:
                return response.text
            else:
                raise Exception("Error generating content with Gemini AI")
        except Exception as e:
            raise Exception(f"Error generating content with Gemini AI: {e}")

    def _prepare_check_prompt(self, check_name: str, check_reference: str) -> list:
        """Prepare the prompt for generating the check."""

        class_name = re.search(
            r"class\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*:", check_reference
        ).group(1)

        prompt_parts = [
            f"Your task is to create a new security check called '{check_name}' for Prowler (a Cloud Security tool).",
            "The control is a Python class that inherits from the Check class and has only one method called execute.",
            "The execute method must return a list of Check_Report_AWS objects.",
            "I need the answer only with Python formatted text.",
            "Use the following check as inspiration to create the new check: ",
            f"{class_name}:",
            check_reference,
            f"{check_name}:",
        ]
        return prompt_parts

    def _prepare_metadata_prompt(self, metadata: dict, context: str) -> list:
        """Prepare the prompt for generating the metadata."""

        metadata.pop("SubServiceName", None)
        metadata["Remediation"]["Code"].pop("NativeIaC", None)
        metadata["Remediation"]["Code"].pop("Other", None)
        metadata["Remediation"]["Code"].pop("Terraform", None)
        metadata.pop("DependsOn", None)
        metadata.pop("RelatedTo", None)

        valid_prowler_categories = [
            "encryption",
            "forensics-ready",
            "internet-exposed",
            "logging",
            "redundancy",
            "secrets",
            "thread-detection",
            "trustboundaries",
            "vulnerability-management",
        ]

        prompt_parts = [
            "Your task is to fill the metadata for a new cybersecurity check in Prowler (a Cloud Security tool).",
            "The metadata is a JSON object with the following fields: ",
            json.dumps(metadata, indent=2),
            "Use the following context sources as inspiration to fill the metadata: ",
            context,
            "The field CheckType should be filled following the format: 'namespace/category/classifier', where namespace, category, and classifier are the values from the following dict: ",
            json.dumps(get_metadata_valid_check_type(metadata["Provider"]), indent=2),
            "One example of a valid CheckType value is: 'Software and Configuration Checks/Vulnerabilities/CVE'. If you don't have a valid value for CheckType, you can leave it empty.",
            "The field ResourceType must be one of the following values:",
            ", ".join(get_metadata_valid_resource_type(metadata["Provider"])),
            "If you don't have a valid value for ResourceType, you can leave it empty.",
            f"The field Category must be one or more of the following values: {', '.join(valid_prowler_categories)}.",
            "I need the answer only with JSON formatted text.",
        ]
        return prompt_parts

    def generate_check(self, check_name: str, check_reference: str) -> str:
        """Fill the check with Gemini AI."""
        if not check_reference:
            return ""

        prompt_parts = self._prepare_check_prompt(check_name, check_reference)
        return (
            self._generate_content(prompt_parts)
            .replace("python", "")
            .replace("```", "")
            .strip()
        )

    def generate_metadata(self, metadata: dict, context: str) -> dict:
        """Fill the metadata with Gemini AI."""
        if not metadata:
            return {}

        prompt_parts = self._prepare_metadata_prompt(metadata, context)
        filled_metadata_json = self._generate_content(prompt_parts)

        # Parse the generated JSON and re-add the removed fields
        filled_metadata = json.loads(
            filled_metadata_json.replace("\n", "")
            .replace("json", "")
            .replace("JSON", "")
            .replace("```", "")
            .strip()
        )

        # Add the removed fields back in the same order

        filled_metadata["Remediation"]["Code"]["NativeIaC"] = ""
        filled_metadata["Remediation"]["Code"]["Other"] = ""
        filled_metadata["Remediation"]["Code"]["Terraform"] = ""

        # Insert key SubServiceName after ServiceName key and RelatedTo and DependsOn just before Notes key

        ordered_filled_metadata = {}

        for key, value in filled_metadata.items():
            ordered_filled_metadata[key] = value
            if key == "ServiceName":
                ordered_filled_metadata["SubServiceName"] = ""
            if key == "Notes":
                ordered_filled_metadata["DependsOn"] = []
                ordered_filled_metadata["RelatedTo"] = []

        return ordered_filled_metadata
