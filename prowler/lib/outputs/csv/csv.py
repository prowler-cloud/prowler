from csv import DictWriter
from typing import Any


# TODO: remove this once we always use the new CSV(Output)
def write_csv(file_descriptor, headers, row):
    csv_writer = DictWriter(
        file_descriptor,
        fieldnames=headers,
        delimiter=";",
    )
    if isinstance(row, dict):
        csv_writer.writerow(row)
    else:
        csv_writer.writerow(row.__dict__)


# TODO: remove this once we always use the new CSV(Output)
def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    # __fields__ is always available in the Pydantic's BaseModel class
    for field in format.__dict__.get("__fields__").keys():
        csv_fields.append(field)
    return csv_fields
