import csv
import json
import sys

file_name_output = sys.argv[1]  # It is the output CSV file
file_name_compliance = sys.argv[2]  # It is the compliance JSON file


number_of_findings_per_pillar = {}
score_per_pillar = {}
# Read the compliance JSON file
with open(file_name_compliance, "r") as file:
    data = json.load(file)

# Read the output CSV file
with open(file_name_output, "r") as file:
    reader = csv.reader(file, delimiter=";")
    headers = next(reader)
    if "CHECK_ID" in headers:
        check_id_index = headers.index("CHECK_ID")
    if "STATUS" in headers:
        status_index = headers.index("STATUS")
    if "MUTED" in headers:
        muted_index = headers.index("MUTED")
    for row in reader:
        for requirement in data["Requirements"]:
            # Take the column that contains the CHECK_ID
            if row[check_id_index] in requirement["Checks"]:
                if (
                    requirement["Attributes"][0]["Section"]
                    not in number_of_findings_per_pillar.keys()
                ):
                    number_of_findings_per_pillar[
                        requirement["Attributes"][0]["Section"]
                    ] = 0
                if (
                    requirement["Attributes"][0]["Section"]
                    not in score_per_pillar.keys()
                ):
                    score_per_pillar[requirement["Attributes"][0]["Section"]] = 0
                if row[status_index] == "FAIL" and row[muted_index] != "TRUE":
                    number_of_findings_per_pillar[
                        requirement["Attributes"][0]["Section"]
                    ] += 1
                    score_per_pillar[
                        requirement["Attributes"][0]["Section"]
                    ] += requirement["Attributes"][0]["LevelOfRisk"]

for key, value in number_of_findings_per_pillar.items():
    print("Pillar:", key)
    print("Score:", score_per_pillar[key] / value)
    print("--------------------------------")
