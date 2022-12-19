from typing import Any


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    for field in format.__dict__.get("__annotations__").keys():
        csv_fields.append(field)
    return csv_fields
