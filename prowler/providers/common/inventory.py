import importlib
import json
import os
import shutil
from collections import deque
from datetime import datetime

from colorama import Fore, Style
from pydantic import BaseModel

from prowler.config.config import orange_color


def run_prowler_inventory(checks_to_execute, provider):
    output_folder_path = f"./output/inventory/{provider}"
    meta_json_file = {}

    os.makedirs(output_folder_path, exist_ok=True)

    # Recursive function to handle serialization
    def class_to_dict(obj, seen=None):
        if seen is None:
            seen = set()

        if isinstance(obj, dict):
            new_dict = {}
            for key, value in obj.items():
                if isinstance(key, tuple):
                    key = str(key)  # Convert tuple to string
                new_dict[key] = class_to_dict(value)
            return new_dict
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, deque):
            return list(class_to_dict(item, seen) for item in obj)
        elif isinstance(obj, BaseModel):
            return obj.dict()
        elif isinstance(obj, (list, tuple)):
            return [class_to_dict(item, seen) for item in obj]
        elif hasattr(obj, "__dict__") and id(obj) not in seen:
            seen.add(id(obj))
            return {
                key: class_to_dict(value, seen) for key, value in obj.__dict__.items()
            }
        else:
            return obj

    service_set = set()

    for check_name in checks_to_execute:
        try:
            service = check_name.split("_")[0]

            if service in service_set:
                continue

            service_set.add(service)

            service_path = f"./prowler/providers/{provider}/services/{service}"

            # List to store all _client filenames
            client_files = []

            # Walk through the directory and find all files
            for root, dirs, files in os.walk(service_path):
                for file in files:
                    if file.endswith("_client.py"):
                        # Append only the filename to the list (not the full path)
                        client_files.append(file)

            service_output_folder = f"{output_folder_path}/{service}"

            os.makedirs(service_output_folder, exist_ok=True)

            for service_client in client_files:

                service_client = service_client.split(".py")[0]
                check_module_path = (
                    f"prowler.providers.{provider}.services.{service}.{service_client}"
                )

                try:
                    lib = importlib.import_module(f"{check_module_path}")
                except ModuleNotFoundError:
                    print(f"Module not found: {check_module_path}")
                    break
                except Exception as e:
                    print(f"Error while importing module {check_module_path}: {e}")
                    break

                client_path = getattr(lib, f"{service_client}")

                if not meta_json_file.get(f"{service}"):
                    meta_json_file[f"{service}"] = []

                # Convert to JSON
                output_file = service_client.split("_client")[0]

                meta_json_file[f"{service}"].append(
                    f"./{service}/{output_file}_output.json"
                )

                with open(
                    f"{service_output_folder}/{output_file}_output.json", "w+"
                ) as fp:
                    output = client_path.__to_dict__()
                    json.dump(output, fp=fp, default=str, indent=4)

        except Exception as e:
            print("Exception: ", e)

    with open(f"{output_folder_path}/output_metadata.json", "w+") as fp:
        json.dump(meta_json_file, fp=fp, default=str, indent=4)

    # end of all things
    folder_to_compress = f"{output_folder_path}"
    output_zip_file = f"{output_folder_path}/prowler-scan-compressed"  # The output file (without extension)

    # Compress the folder into a zip file
    shutil.make_archive(f"{output_zip_file}", "zip", folder_to_compress)
    print(
        f"\n{Style.BRIGHT}{Fore.GREEN}Scan inventory for {provider} results: {orange_color}{output_folder_path}"
    )
