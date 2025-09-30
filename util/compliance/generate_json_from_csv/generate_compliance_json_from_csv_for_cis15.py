import csv
import json
import sys

# Convert a CSV file following the CIS 1.5 AWS benchmark into a Prowler v3.0 Compliance JSON file
# CSV fields:
# ID	Title	Check	Section #	SubSection	Profile	Assessment Status	Description	Rationale Statement	Impact Statement	Remediation Procedure	Audit Procedure	Additional Information	References	Default Value

# get the CSV filename to convert from
file_name = sys.argv[1]

# read the CSV file rows and use the column fields to form the Prowler compliance JSON file 'ens_rd2022_aws.json'
output = {"Framework": "CIS-AWS", "Version": "1.5", "Requirements": []}
with open(file_name, newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        if len(row[4]) > 0:
            attribute = {
                "Section": row[3],
                "SubSection": row[4],
                "Profile": row[5],
                "AssessmentStatus": row[6],
                "Description": row[7],
                "RationaleStatement": row[8],
                "ImpactStatement": row[9],
                "RemediationProcedure": row[10],
                "AuditProcedure": row[11],
                "AdditionalInformation": row[12],
                "References": row[13],
                "DefaultValue": row[14],
            }
        else:
            attribute = {
                "Section": row[3],
                "Profile": row[5],
                "AssessmentStatus": row[6],
                "Description": row[7],
                "RationaleStatement": row[8],
                "ImpactStatement": row[9],
                "RemediationProcedure": row[10],
                "AuditProcedure": row[11],
                "AdditionalInformation": row[12],
                "References": row[13],
                "DefaultValue": row[14],
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
