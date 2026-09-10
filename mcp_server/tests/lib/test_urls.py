"""Tests for the shared URL path builder.

The bug these pin: an identifier interpolated into a path was resolved away by
httpx per RFC 3986, so "../" reached an endpoint no tool meant to call.
"""

import pytest

from prowler_mcp_server.lib.urls import path_segment, url_path


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("s3_bucket_public_access", "s3_bucket_public_access"),
        ("cis_4.0_aws", "cis_4.0_aws"),
        ("../../evil", "..%2F..%2Fevil"),
        ("....//evil", "....%2F%2Fevil"),
        ("%2e%2e%2f", "%252e%252e%252f"),
        ("..;/", "..%3B%2F"),
        ("s3/../evil", "s3%2F..%2Fevil"),
        ("evil?fields=all", "evil%3Ffields%3Dall"),
        ("evil#frag", "evil%23frag"),
        ("evil\\wrong", "evil%5Cwrong"),
        ("two words", "two%20words"),
    ],
    ids=[
        "plain",
        "dots-in-a-name",
        "traversal",
        "stripped-filter-bypass",
        "already-encoded",
        "path-parameter",
        "mid-path",
        "query",
        "fragment",
        "backslash",
        "space",
    ],
)
def test_a_segment_survives_as_a_name_and_never_as_syntax(value, expected):
    """A real ID passes through untouched; URL syntax comes back as characters."""
    assert path_segment(value) == expected


@pytest.mark.parametrize("value", [".", ".."], ids=["here", "up-one"])
def test_a_segment_of_nothing_but_dots_is_escaped_rather_than_left_to_resolve(value):
    """`quote` keeps a dot, so a segment of only dots would still resolve away."""
    assert path_segment(value) == value.replace(".", "%2E")


def test_a_path_is_the_segments_it_was_given_and_no_others():
    """One argument per segment, so no call site has to encode anything."""
    assert url_path("users", "../../evil", "roles") == "/users/..%2F..%2Fevil/roles"


def test_a_single_segment_path_keeps_its_leading_slash():
    """Every caller joins this onto a base URL that ends without a slash."""
    assert url_path("providers") == "/providers"
