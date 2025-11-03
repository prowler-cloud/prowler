"""
Script to convert CCC security controls YAML files to JSON format.
"""

import json
import sys
from pathlib import Path

import yaml


def load_yaml(file_path):
    """Load YAML file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Error loading YAML file: {e}")
        return None


def transform_yaml_to_json(yaml_data):
    """Transform YAML structure to JSON."""

    result = {
        "Framework": "CCC",
        "Version": "",
        "Provider": "<todo>",
        "Description": "The best practices for Common Cloud Controls Catalog (CCC) for <todo>",
        "Requirements": [],
    }

    control_families = yaml_data.get("control-families", [])

    for family in control_families:
        family_name = family.get("title", "")
        family_description = family.get("description", "")
        controls = family.get("controls", [])

        for control in controls:
            control_id = control.get("id", "")
            control_title = control.get("title", "")
            control_objective = control.get("objective", "")

            threat_mappings = control.get("threat-mappings", [])
            guideline_mappings = control.get("guideline-mappings", [])

            assessment_reqs = control.get("assessment-requirements", [])

            for req in assessment_reqs:
                req_id = req.get("id", "")
                req_text = req.get("text", "").strip()
                applicability = req.get("applicability", [])
                recommendation = req.get("recommendation", "")

                section_threat_mappings = []
                for tm in threat_mappings:
                    ref_id = tm.get("reference-id", "")
                    entries = tm.get("entries", [])
                    identifiers = []
                    for entry in entries:
                        entry_ref = entry.get("reference-id", "")
                        if entry_ref:
                            if "Core." in entry_ref:
                                entry_ref = entry_ref.replace("Core.", "")
                            identifiers.append(entry_ref)

                    if identifiers:
                        section_threat_mappings.append(
                            {"ReferenceId": ref_id, "Identifiers": identifiers}
                        )

                section_guideline_mappings = []
                for gm in guideline_mappings:
                    ref_id = gm.get("reference-id", "")
                    entries = gm.get("entries", [])
                    identifiers = []
                    for entry in entries:
                        entry_ref = entry.get("reference-id", "")
                        if entry_ref:
                            identifiers.append(entry_ref)

                    if identifiers:
                        section_guideline_mappings.append(
                            {"ReferenceId": ref_id, "Identifiers": identifiers}
                        )

                checks = []

                requirement = {
                    "Id": req_id,
                    "Description": req_text,
                    "Attributes": [
                        {
                            "FamilyName": family_name,
                            "FamilyDescription": family_description,
                            "Section": f"{control_id} {control_title}",
                            "SubSection": "",
                            "SubSectionObjective": control_objective.strip(),
                            "Applicability": applicability,
                            "Recommendation": recommendation,
                            "SectionThreatMappings": section_threat_mappings,
                            "SectionGuidelineMappings": section_guideline_mappings,
                        }
                    ],
                    "Checks": checks,
                }

                result["Requirements"].append(requirement)

    return result


def save_json(data, file_path):
    """Save data as JSON."""
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving JSON file: {e}")
        return False


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python from_yaml_to_json.py <yaml_file> [output_file.json]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output.json"

    if not Path(input_file).exists():
        print(f"Error: File {input_file} does not exist.")
        sys.exit(1)

    print(f"Loading {input_file}...")
    yaml_data = load_yaml(input_file)

    if yaml_data is None:
        print("Could not load YAML file.")
        sys.exit(1)

    print("Transforming YAML to JSON...")
    json_data = transform_yaml_to_json(yaml_data)

    print(f"Saving result to {output_file}...")
    if save_json(json_data, output_file):
        print("Conversion completed successfully!")
        print(f"Generated file: {output_file}")
        print(f"Total requirements processed: {len(json_data['Requirements'])}")
    else:
        print("Error saving JSON file.")
        sys.exit(1)


if __name__ == "__main__":
    main()
