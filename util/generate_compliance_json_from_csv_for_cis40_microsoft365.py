import csv
import json
import sys

# Convert a CSV file following the CIS 4.0 M365 Benchmark into a Prowler v3.0 Compliance JSON file
# CSV fields:
# Section #,Recommendation #,Profile,Title,Assessment Status,Description,Rationale Statement,Impact Statement,Remediation Procedure,Audit Procedure,Additional Information,CIS Controls,CIS Safeguards 1 (v8),CIS Safeguards 2 (v8),CIS Safeguards 3 (v8),v8 IG1,v8 IG2,v8 IG3,CIS Safeguards 1 (v7),CIS Safeguards 2 (v7),CIS Safeguards 3 (v7),v7 IG1,v7 IG2,v7 IG3,References,Default Value

# Get the CSV filename to convert from
file_name = sys.argv[1]

# Create the output JSON object
output = {"Framework": "CIS", "Version": "4.0", "Requirements": []}

# Open the CSV file and read the rows
try:
    with open(file_name, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter=",")
        next(reader)  # Skip the header row
        for row in reader:
            attribute = {
                "Section": row[0],
                "Profile": row[2],
                "AssessmentStatus": row[4],
                "Description": row[5],
                "RationaleStatement": row[6],
                "ImpactStatement": row[7],
                "RemediationProcedure": row[8],
                "AuditProcedure": row[9],
                "AdditionalInformation": row[10],
                "References": row[24],
            }
            if row[4] != "":
                output["Requirements"].append(
                    {
                        "Id": row[1],
                        "Description": row[5],
                        "Checks": [],
                        "Attributes": [attribute],
                    }
                )
except UnicodeDecodeError:
    # If there is an error reading the file with the default encoding, try with ISO-8859-1
    with open(file_name, newline="", encoding="ISO-8859-1") as f:
        reader = csv.reader(f, delimiter=",")
        next(reader)  # Skip the header row
        for row in reader:
            attribute = {
                "Section": row[0],
                "Profile": row[2],
                "AssessmentStatus": row[4],
                "Description": row[5],
                "RationaleStatement": row[6],
                "ImpactStatement": row[7],
                "RemediationProcedure": row[8],
                "AuditProcedure": row[9],
                "AdditionalInformation": row[10],
                "References": row[24],
            }
            if row[4] != "":
                output["Requirements"].append(
                    {
                        "Id": row[1],
                        "Description": row[5],
                        "Checks": [],
                        "Attributes": [attribute],
                    }
                )

# Save the output JSON file
with open("cis_4.0_m365.json", "w", encoding="utf-8") as outfile:
    json.dump(output, outfile, indent=4, ensure_ascii=False)

print("Archivo JSON generado exitosamente.")
