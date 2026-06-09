import logging

import pytest

from prowler.providers.aws.lib.resource_limit.resource_limit import ResourceScanLimiter


def test_missing_config_is_unlimited():
    limiter = ResourceScanLimiter({}, "ec2")

    assert limiter.limit_for("snapshot") is None
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


def test_null_and_zero_limits_are_unlimited():
    config = {
        "resource_scan_limits": {
            "default": 0,
            "services": {
                "ec2": {
                    "default": None,
                    "resource_types": {"snapshot": 0},
                }
            },
        }
    }
    limiter = ResourceScanLimiter(config, "ec2")

    assert limiter.limit_for("snapshot") is None
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


def test_provider_default_applies():
    limiter = ResourceScanLimiter(
        {"resource_scan_limits": {"default": 1}},
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 1
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_service_default_overrides_provider_default():
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 1,
                "services": {"ec2": {"default": 2}},
            }
        },
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 2
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_resource_type_override_overrides_service_default():
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 1,
                "services": {
                    "ec2": {
                        "default": 2,
                        "resource_types": {"snapshot": 3},
                    }
                },
            }
        },
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 3
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_null_service_and_resource_placeholders_do_not_mask_provider_default():
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 2,
                "services": {
                    "ec2": {
                        "default": None,
                        "resource_types": {"snapshot": None},
                    }
                },
            }
        },
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 2
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_null_resource_type_placeholder_does_not_mask_service_default():
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 1,
                "services": {
                    "ec2": {
                        "default": 2,
                        "resource_types": {"snapshot": None},
                    }
                },
            }
        },
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 2
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_real_config_shape_null_placeholders_do_not_mask_provider_default():
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 2,
                "services": {
                    "awslambda": {
                        "default": None,
                        "resource_types": {"function": None},
                    },
                    "backup": {
                        "default": None,
                        "resource_types": {"recovery_point": None},
                    },
                    "cloudwatch": {
                        "default": None,
                        "resource_types": {"log_group": None},
                    },
                    "codeartifact": {
                        "default": None,
                        "resource_types": {"package": None},
                    },
                    "ec2": {
                        "default": None,
                        "resource_types": {"snapshot": None},
                    },
                    "ecs": {
                        "default": None,
                        "resource_types": {"task_definition": None},
                    },
                },
            }
        },
        "ec2",
    )

    assert limiter.limit_for("snapshot") == 2
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")
    assert not limiter.allow("snapshot")


def test_invalid_resource_type_override_disables_lower_precedence_limits(caplog):
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": 1,
                "services": {
                    "ec2": {
                        "default": 1,
                        "resource_types": {"snapshot": "invalid"},
                    }
                },
            }
        },
        "ec2",
    )

    with caplog.at_level(logging.WARNING):
        assert limiter.limit_for("snapshot") is None

    assert "Invalid AWS resource scan limit" in caplog.text
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


def test_invalid_values_warn_and_resolve_to_unlimited(caplog):
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "default": -1,
                "services": {
                    "ec2": {
                        "default": "two",
                        "resource_types": {"snapshot": "invalid"},
                    }
                },
            }
        },
        "ec2",
    )

    with caplog.at_level(logging.WARNING):
        assert limiter.limit_for("snapshot") is None

    assert "Invalid AWS resource scan limit" in caplog.text
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


@pytest.mark.parametrize("raw_limit", [True, False])
def test_bool_values_warn_and_resolve_to_unlimited(caplog, raw_limit):
    limiter = ResourceScanLimiter(
        {
            "resource_scan_limits": {
                "services": {
                    "ec2": {
                        "resource_types": {"snapshot": raw_limit},
                    }
                }
            }
        },
        "ec2",
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert limiter.limit_for("snapshot") is None

    assert "Invalid AWS resource scan limit" in caplog.text
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


def test_explicit_resource_arn_source_bypasses_limits():
    limiter = ResourceScanLimiter(
        {"resource_scan_limits": {"default": 1}},
        "ec2",
        bypass_limits=True,
    )

    assert limiter.limit_for("snapshot") is None
    assert limiter.allow("snapshot")
    assert limiter.allow("snapshot")


def test_active_limits_emit_runtime_warning(caplog):
    with caplog.at_level(logging.WARNING):
        ResourceScanLimiter({"resource_scan_limits": {"default": 1}}, "ec2")

    assert "AWS resource scan limits are active" in caplog.text
    assert "compliance results may be incomplete" in caplog.text


def test_explicit_resource_arn_bypass_does_not_emit_runtime_warning(caplog):
    with caplog.at_level(logging.WARNING):
        ResourceScanLimiter(
            {"resource_scan_limits": {"default": 1}},
            "ec2",
            bypass_limits=True,
        )

    assert "AWS resource scan limits are active" not in caplog.text
