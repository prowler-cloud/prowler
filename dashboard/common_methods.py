import re
from dashboard.config import pass_emoji, fail_emoji, info_emoji, manual_emoji


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
        return fail_emoji
    elif status == "PASS":
        return pass_emoji
    elif status == "INFO":
        return info_emoji
    elif status == "MANUAL":
        return manual_emoji
    return status
