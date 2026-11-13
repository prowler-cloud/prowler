import pytest

from prowler.providers.azure.lib.runtime.runtime_version import (
    parse_java_version,
    parse_runtime_version,
    runtime_version_at_least,
)


class Test_runtime_version_helpers:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("PHP|8.3", (8, 3)),
            ("php|8.0", (8, 0)),
            ("PYTHON|3.12", (3, 12)),
            ("8.2.35", (8, 2, 35)),
            ("", ()),
            (None, ()),
            ("PHP|latest", ()),
        ],
    )
    def test_parse_runtime_version(self, value, expected):
        assert parse_runtime_version(value) == expected

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("JAVA|17-java17", (17,)),
            ("TOMCAT|10.0-java11", (11,)),
            ("JBOSSEAP|7-java8", (8,)),
            ("JAVA|8-jre8", (8,)),
            ("java1.8", (8,)),
            ("17", (17,)),
            ("", ()),
        ],
    )
    def test_parse_java_version(self, value, expected):
        assert parse_java_version(value) == expected

    @pytest.mark.parametrize(
        "current,minimum,expected",
        [
            ((8, 3), (8, 2), True),
            ((8, 2), (8, 2), True),
            ((8, 1), (8, 2), False),
            ((8, 2), (8, 2, 35), True),
            ((9,), (8, 2), True),
            ((), (8, 2), False),
            ((8, 2), (), False),
        ],
    )
    def test_runtime_version_at_least(self, current, minimum, expected):
        assert runtime_version_at_least(current, minimum) is expected
