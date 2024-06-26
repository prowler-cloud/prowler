import csv
import json
import sys

# Convert a CSV file following the CIS 1.5 AWS benchmark into a Prowler v3.0 Compliance JSON file
# CSV fields:
# Id, Title,Checks,Attributes_Section,Attributes_Level,Attributes_AssessmentStatus,Attributes_Description,Attributes_RationalStatement,Attributes_ImpactStatement,Attributes_RemediationProcedure,Attributes_AuditProcedure,Attributes_AdditionalInformation,Attributes_References

# get the CSV filename to convert from
file_name = sys.argv[1]

# read the CSV file rows and use the column fields to form the Prowler compliance JSON file 'ens_rd2022_aws.json'
output = {"Framework": "CIS-GCP", "Version": "2.0", "Requirements": []}
with open(file_name, newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        attribute = {
            "Section": row[0],
            "Profile": row[2],
            "AssessmentStatus": row[6],
            "Description": row[9],
            "RationaleStatement": row[10],
            "ImpactStatement": row[11],
            "RemediationProcedure": row[12],
            "AuditProcedure": row[13],
            "AdditionalInformation": row[14],
            "References": row[28],
        }
        output["Requirements"].append(
            {
                "Id": row[1],
                "Description": row[9],
                "Checks": list(map(str.strip, row[4].split(","))),
                "Attributes": [attribute],
            }
        )

# Write the output Prowler compliance JSON file 'cis_2.0_gcp.json' locally
with open("cis_2.0_gcp.json", "w", encoding="utf-8") as outfile:
    json.dump(output, outfile, indent=4, ensure_ascii=False)
