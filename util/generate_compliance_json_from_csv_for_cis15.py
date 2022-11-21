import csv
import json
import sys

# Convert a CSV file following the CIS 1.5 AWS benchmark into a Prowler v3.0 Compliance JSON file
# CSV fields:
# Id, Title,Checks,Attributes_Section,Attributes_Level,Attributes_AssessmentStatus,Attributes_Description,Attributes_RationalStatement,Attributes_ImpactStatement,Attributes_RemediationProcedure,Attributes_AuditProcedure,Attributes_AdditionalInformation,Attributes_References

# get the CSV filename to convert from
file_name = sys.argv[1]

# read the CSV file rows and use the column fields to form the Prowler compliance JSON file 'ens_rd2022_aws.json'
output = {"Framework": "CIS-AWS", "Version": "1.5", "Requirements": []}
with open(file_name, newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        attribute = {
            "Section": row[3],
            "Profile": row[4],
            "AssessmentStatus": row[5],
            "Description": row[6],
            "RationaleStatement": row[7],
            "ImpactStatement": row[8],
            "RemediationProcedure": row[9],
            "AuditProcedure": row[10],
            "AdditionalInformation": row[11],
            "References": row[12],
        }
        output["Requirements"].append(
            {
                "Id": row[0],
                "Description": row[1],
                "Checks": list(map(str.strip, row[2].split(","))),
                "Attributes": [attribute],
            }
        )

# Write the output Prowler compliance JSON file 'cis_1.5_aws.json' locally
with open("cis_1.5_aws.json", "w", encoding="utf-8") as outfile:
    json.dump(output, outfile, indent=4, ensure_ascii=False)
