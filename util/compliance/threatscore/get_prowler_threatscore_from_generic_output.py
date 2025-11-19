import csv
import json
import sys

file_name_output = sys.argv[1]
file_name_compliance = sys.argv[2]


score_per_pillar = {}
max_score_per_pillar = {}
counted_req_ids = []
to_fix = ""

with open(file_name_compliance, "r") as file:
    data = json.load(file)


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
            # Avoid counting the same requirement twice
            if requirement["Id"] in counted_req_ids:
                continue

            if row[check_id_index] in requirement["Checks"]:
                if (
                    requirement["Attributes"][0]["Section"]
                    not in score_per_pillar.keys()
                ):
                    score_per_pillar[requirement["Attributes"][0]["Section"]] = 0
                    max_score_per_pillar[requirement["Attributes"][0]["Section"]] = 0
                if row[status_index] == "FAIL" and row[muted_index] != "TRUE":
                    max_score_per_pillar[requirement["Attributes"][0]["Section"]] += (
                        requirement["Attributes"][0]["LevelOfRisk"]
                        * requirement["Attributes"][0]["Weight"]
                    )
                    counted_req_ids.append(requirement["Id"])
                    if requirement["Attributes"][0]["Weight"] >= 100:
                        to_fix += (
                            requirement["Id"]
                            + " - "
                            + requirement["Description"]
                            + "\n"
                        )
                else:
                    if row[status_index] == "PASS" and row[muted_index] != "TRUE":
                        score_per_pillar[requirement["Attributes"][0]["Section"]] += (
                            requirement["Attributes"][0]["LevelOfRisk"]
                            * requirement["Attributes"][0]["Weight"]
                        )
                        max_score_per_pillar[
                            requirement["Attributes"][0]["Section"]
                        ] += (
                            requirement["Attributes"][0]["LevelOfRisk"]
                            * requirement["Attributes"][0]["Weight"]
                        )
                        counted_req_ids.append(requirement["Id"])

for key in score_per_pillar.keys():
    print("Pillar:", key)
    print("Score:", score_per_pillar[key] / max_score_per_pillar[key] * 100)
    print("--------------------------------")

print("Threats to fix ASAP (weight >= 100):")
print(to_fix)
