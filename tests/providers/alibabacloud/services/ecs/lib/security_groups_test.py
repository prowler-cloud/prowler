from prowler.providers.alibabacloud.services.ecs.lib.security_groups import (
    port_in_range,
)


def test_single_port_and_range():
    assert port_in_range("22/22", 22)
    assert port_in_range("22", 22)
    assert port_in_range("1/65535", 3389)
    assert not port_in_range("80/90", 22)


def test_alibaba_all_port_range():
    assert port_in_range("-1/-1", 22)
    assert port_in_range("-1/-1", 3389)
    assert port_in_range(" -1/-1 ", 22)
    assert port_in_range("-1", 22)


def test_invalid_port_range():
    assert not port_in_range("", 22)
    assert not port_in_range("abc", 22)
    assert not port_in_range("1/nope", 22)
