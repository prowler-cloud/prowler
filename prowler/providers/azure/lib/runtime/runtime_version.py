import re

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")
_JAVA_SUFFIX_RE = re.compile(r"-(?:java|jre)(\d+)", re.IGNORECASE)


def parse_runtime_version(value) -> tuple[int, ...]:
    """Return the first dotted number in a stack string as an int tuple, empty if none."""
    match = _VERSION_RE.search("" if value is None else str(value))
    return tuple(int(part) for part in match.group().split(".")) if match else ()


def parse_java_version(value) -> tuple[int, ...]:
    """Java major from 'JAVA|17-java17', 'TOMCAT|10.0-java11', '1.8' or '17'."""
    match = _JAVA_SUFFIX_RE.search("" if value is None else str(value))
    if match:
        return (int(match.group(1)),)
    version = parse_runtime_version(value)
    # Legacy '1.8' naming for Java 8
    if len(version) > 1 and version[0] == 1:
        return (version[1],)
    return version[:1]


def runtime_version_at_least(
    current: tuple[int, ...], minimum: tuple[int, ...]
) -> bool:
    """Compare only the components the platform exposes (no patch level in linuxFxVersion)."""
    if not current or not minimum:
        return False
    length = min(len(current), len(minimum))
    return current[:length] >= minimum[:length]
