import csv
import json
import sys

# Convert a CSV file following the Spanish ENS - Esquema Nacional de Seguridad - RD2022 benchmark into a Prowler v3.0 Compliance JSON file
# CSV fields:
# ['Id', 'Description', 'Marco', 'Categoria', 'Descripcion_Control', 'Nivel', 'Dimensiones', 'Checks', 'ChecksV2', 'Tipo'],

# get the CSV filename to convert from
file_name = sys.argv[1]

# read the CSV file rows and use the column fields to form the Prowler compliance JSON file 'ens_rd2022_aws.json'
output = {"Framework": "ENS", "Version": "RD2022", "Requirements": []}
with open(file_name, newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        niveles = list(map(str.strip, row[5].split(",")))
        # Use of pytec/CPSTIC levels is under clarification, disabling temporarily
        # if "pytec" in niveles:
        #     nivelvalue = "pytec"
        # el
        if "alto" in niveles:
            nivelvalue = "alto"
        elif "medio" in niveles:
            nivelvalue = "medio"
        elif "opcional" in niveles:
            nivelvalue = "opcional"
        else:
            nivelvalue = "bajo"

        attribute = {
            "IdGrupoControl": row[10],
            "Marco": row[2],
            "Categoria": row[3],
            "DescripcionControl": row[4],
            "Nivel": nivelvalue,
            "Tipo": row[9],
            "Dimensiones": list(map(str.strip, row[6].split(","))),
            "ModoEjecucion": row[11],
        }
        output["Requirements"].append(
            {
                "Id": row[0],
                "Description": row[1],
                "Attributes": [attribute],
                "Checks": list(map(str.strip, row[7].split(","))),
            }
        )

# Write the output Prowler compliance JSON file 'ens_rd2022_aws.json' locally
with open("ens_rd2022_aws.json", "w", encoding="utf-8") as outfile:
    json.dump(output, outfile, indent=4, ensure_ascii=False)
