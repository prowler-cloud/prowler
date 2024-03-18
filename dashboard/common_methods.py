import re


def version_tuple(version):
    version = re.sub("[a-zA-Z]", "", version)
    if version == "" or version == "-" or version == " " or version == "_":
        return version
    else:
        if "." in version:
            delimiter = "."
        elif "-" in version:
            delimiter = "-"
        elif "_" in version:
            delimiter = "_"
        else:
            delimiter = None

        # clean up all the strings that end with . or - or _ (few cases)
        while version[-1] == ".":
            version = version.replace(".", "", 1)

        while version[-1] == "-":
            version = version.replace("-", "", 1)

        while version[-1] == "_":
            version = version.replace("_", "", 1)

        if delimiter:
            return tuple(
                int(segment) for segment in version.split(delimiter) if segment
            )
        else:
            return version


def map_status_to_icon(status):
    if status == "FAIL":
        return "❌"
    elif status == "PASS":
        return "✅"
    elif status == "INFO":
        return "ℹ️"
    return status
