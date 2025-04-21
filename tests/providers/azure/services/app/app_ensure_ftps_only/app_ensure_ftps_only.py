import subprocess
import json

# Run `az webapp list` and parse output
apps_raw = subprocess.check_output([
    "az", "webapp", "list",
    "--query", "[].{name:name,resourceGroup:resourceGroup}",
    "-o", "json"
])
apps = json.loads(apps_raw)

# Loop over each app
for app in apps:
    name = app["name"]
    rg = app["resourceGroup"]

    # Get ftpsState for each app
    ftp_raw = subprocess.check_output([
        "az", "webapp", "config", "show",
        "--resource-group", rg,
        "--name", name,
        "--query", "ftpsState",
        "-o", "tsv"
    ])
    ftp = ftp_raw.decode().strip()

    if ftp == "AllAllowed":
        print(f"Fail")
