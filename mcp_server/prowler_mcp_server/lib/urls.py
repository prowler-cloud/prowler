"""URL construction shared by every sub-server.

An identifier joined into a path unencoded is not sent as itself: httpx resolves
the URL per RFC 3986, so "../" walks the request onto another endpoint.
"""

from urllib.parse import quote

_DOT_SEGMENTS = frozenset({".", ".."})


def path_segment(value: str) -> str:
    """Encode one path segment, so an identifier names a resource and nothing else.

    Args:
        value: The segment to encode, taken as a name in full.

    Returns:
        The segment percent-encoded, with the dots escaped when it is only dots.
    """
    encoded = quote(value, safe="")
    # A dot is legal in a name, so `quote` keeps it: a segment of nothing but
    # dots would still resolve away rather than name anything.
    return encoded.replace(".", "%2E") if encoded in _DOT_SEGMENTS else encoded


def url_path(*segments: str) -> str:
    """Build a URL path from one argument per segment, each of them encoded.

    Args:
        *segments: The path segments, in order.

    Returns:
        The joined path, with a leading slash.
    """
    return "/" + "/".join(path_segment(segment) for segment in segments)
