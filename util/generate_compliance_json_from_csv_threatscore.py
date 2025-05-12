import csv
import json
import sys

# Convert a CSV file following the ThreatScore CSV format into a Prowler Compliance JSON file
# CSV fields:
# Id, Title, Description, Section, SubSection, AttributeDescription, AdditionalInformation, LevelOfRisk, Checks

# get the CSV filename to convert from
file_name = sys.argv[1]

# read the CSV file rows and use the column fields to form the Prowler compliance JSON file 'prowler_threatscore_aws.json'
output = {"Framework": "ProwlerThreatScore", "Version": "1.0", "Requirements": []}
with open(file_name, newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        attribute = {
            "Title": row[1],
            "Section": row[3],
            "SubSection": row[4],
            "AttributeDescription": row[5],
            "AdditionalInformation": row[6],
            "LevelOfRisk": row[7],
        }
        output["Requirements"].append(
            {
                "Id": row[0],
                "Description": row[2],
                "Checks": list(map(str.strip, row[8].split(","))),
                "Attributes": [attribute],
            }
        )

# Write the output Prowler compliance JSON file 'prowler_threatscore_aws.json' locally
with open("prowler_threatscore_azure.json", "w", encoding="utf-8") as outfile:
    json.dump(output, outfile, indent=4, ensure_ascii=False)
