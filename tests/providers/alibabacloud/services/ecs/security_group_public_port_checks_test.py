import importlib
import json
from unittest import mock

import pytest

from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService
from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)

PORT_CHECKS = (
    (
        "ecs_securitygroup_restrict_high_risk_ports_internet",
        (25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088),
        "high-risk TCP ports",
    ),
    ("ecs_securitygroup_restrict_telnet_internet", (23,), "Telnet TCP port 23"),
    ("ecs_securitygroup_restrict_mysql_internet", (3306,), "MySQL TCP port 3306"),
    (
        "ecs_securitygroup_restrict_postgresql_internet",
        (5432,),
        "PostgreSQL TCP port 5432",
    ),
    (
        "ecs_securitygroup_restrict_sql_server_internet",
        (1433, 1434),
        "SQL Server TCP ports 1433 and 1434",
    ),
    (
        "ecs_securitygroup_restrict_oracle_internet",
        (1521, 2483),
        "Oracle Database TCP ports 1521 and 2483",
    ),
    (
        "ecs_securitygroup_restrict_mongodb_internet",
        (27017, 27018),
        "MongoDB TCP ports 27017 and 27018",
    ),
    (
        "ecs_securitygroup_restrict_cassandra_internet",
        (7199, 9160, 8888),
        "Cassandra TCP ports 7199, 9160, and 8888",
    ),
    ("ecs_securitygroup_restrict_redis_internet", (6379,), "Redis TCP port 6379"),
    (
        "ecs_securitygroup_restrict_ftp_internet",
        (20, 21),
        "FTP TCP ports 20 and 21",
    ),
    (
        "ecs_securitygroup_restrict_elasticsearch_kibana_internet",
        (9200, 9300, 5601),
        "Elasticsearch and Kibana TCP ports 9200, 9300, and 5601",
    ),
    ("ecs_securitygroup_restrict_kafka_internet", (9092,), "Kafka TCP port 9092"),
    (
        "ecs_securitygroup_restrict_memcached_internet",
        (11211,),
        "Memcached TCP port 11211",
    ),
)
RUNTIME_PORT_CHECKS = PORT_CHECKS + (
    ("ecs_securitygroup_restrict_ssh_internet", (22,), "SSH TCP port 22"),
    (
        "ecs_securitygroup_restrict_rdp_internet",
        (3389,),
        "Microsoft RDP TCP port 3389",
    ),
)
PORT_CASES = tuple(
    (check_id, expected_ports, message, target_port)
    for check_id, expected_ports, message in RUNTIME_PORT_CHECKS
    for target_port in expected_ports
)


def _configure_failed_check_state(mocked_client):
    service = object.__new__(AlibabaCloudService)
    service.failed_checks = set()
    mocked_client.set_failed_check.side_effect = service.set_failed_check
    mocked_client.is_failed_check.side_effect = service.is_failed_check


def _security_group(group_id, ingress_rules):
    from prowler.providers.alibabacloud.services.ecs.ecs_service import SecurityGroup

    return SecurityGroup(
        id=group_id,
        name=f"name-{group_id}",
        region="cn-hangzhou",
        arn=f"arn:sg/{group_id}",
        ingress_rules=ingress_rules,
    )


@pytest.mark.parametrize("check_id,expected_ports,message", PORT_CHECKS)
def test_public_port_check_fail_and_pass_wiring(check_id, expected_ports, message):
    module_path = f"prowler.providers.alibabacloud.services.ecs.{check_id}.{check_id}"
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        check_module = importlib.import_module(module_path)
        check_class = getattr(check_module, check_id)

        assert check_module.CHECK_PORTS == expected_ports

        failing_group = _security_group(
            "sg-fail",
            [
                {
                    "policy": "Accept",
                    "ip_protocol": "tcp",
                    "ipv_6source_cidr_ip": "::/0",
                    "port_range": f"{expected_ports[-1]}/{expected_ports[-1]}",
                }
            ],
        )
        passing_group = _security_group(
            "sg-pass",
            [
                {
                    "policy": "Accept",
                    "ip_protocol": "tcp",
                    "source_cidr_ip": "0.0.0.0/0",
                    "port_range": "1/1",
                }
            ],
        )
        mocked_client = mock.MagicMock()
        mocked_client.security_groups = {
            failing_group.arn: failing_group,
            passing_group.arn: passing_group,
        }

        with mock.patch.object(check_module, "ecs_client", mocked_client):
            result = check_class().execute()

    assert len(result) == 2
    assert result[0].status == "FAIL"
    assert result[0].resource_id == "sg-fail"
    assert result[0].resource_arn == "arn:sg/sg-fail"
    assert result[0].region == "cn-hangzhou"
    service_name = message.split(" TCP ")[0]
    assert result[0].status_extended == (
        f"Security group name-sg-fail (sg-fail) has {service_name} TCP port "
        f"{expected_ports[-1]} open to the internet (0.0.0.0/0 or ::/0)."
    )
    assert result[1].status == "PASS"
    assert result[1].resource_id == "sg-pass"
    assert message in result[1].status_extended
    assert "does not have" in result[1].status_extended


@pytest.mark.parametrize("check_id,expected_ports,message", PORT_CHECKS)
def test_public_port_check_metadata_has_exact_rule_guidance(
    check_id, expected_ports, message
):
    module_path = f"prowler.providers.alibabacloud.services.ecs.{check_id}.{check_id}"
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        check_module = importlib.import_module(module_path)
        check_class = getattr(check_module, check_id)
        metadata = json.loads(check_class().metadata())
        remediation_code = metadata["Remediation"]["Code"]

    assert remediation_code["CLI"] == ""
    guidance = remediation_code["Other"]
    for port in expected_ports:
        assert str(port) in guidance
    assert "TCP or ALL" in guidance
    assert "exact rule" in guidance.lower()
    assert "exactly match" in guidance.lower()


@pytest.mark.parametrize("check_id,expected_ports,message,target_port", PORT_CASES)
@pytest.mark.parametrize(
    "rule,expected_status",
    [
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
            },
            "FAIL",
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "ipv_6source_cidr_ip": "::/0",
            },
            "FAIL",
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "10.0.0.0/8",
            },
            "PASS",
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "udp",
                "source_cidr_ip": "0.0.0.0/0",
            },
            "PASS",
        ),
        (
            {
                "policy": "Drop",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
            },
            "PASS",
        ),
    ],
)
def test_every_target_port_base_rule_semantics(
    check_id, expected_ports, message, target_port, rule, expected_status
):
    tested_rule = {**rule, "port_range": f"{target_port}/{target_port}"}
    result = _execute_check(check_id, [tested_rule])

    assert result.status == expected_status
    if expected_status == "FAIL":
        assert f"TCP port {target_port} open" in result.status_extended
        assert message.split(" TCP ")[0] in result.status_extended


@pytest.mark.parametrize("check_id,expected_ports,message,target_port", PORT_CASES)
@pytest.mark.parametrize(
    "port_range,expected_status",
    [
        ("1/1", "PASS"),
        ("{lower}/{upper}", "FAIL"),
    ],
)
def test_every_target_port_range_inclusion_and_exclusion(
    check_id, expected_ports, message, target_port, port_range, expected_status
):
    if "{" in port_range:
        ordered_ports = sorted(expected_ports)
        target_index = ordered_ports.index(target_port)
        previous_port = ordered_ports[target_index - 1] if target_index > 0 else 0
        next_port = (
            ordered_ports[target_index + 1]
            if target_index < len(ordered_ports) - 1
            else 65536
        )
        port_range = port_range.format(
            lower=max(previous_port + 1, target_port - 1),
            upper=min(next_port - 1, target_port + 1),
        )
    result = _execute_check(
        check_id,
        [
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": port_range,
            }
        ],
    )

    assert result.status == expected_status
    if expected_status == "FAIL":
        assert f"TCP port {target_port} open" in result.status_extended


def _execute_check(check_id, ingress_rules, ingress_rules_complete=True):
    module_path = f"prowler.providers.alibabacloud.services.ecs.{check_id}.{check_id}"
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        check_module = importlib.import_module(module_path)
        check_class = getattr(check_module, check_id)
        security_group = _security_group("sg-runtime", ingress_rules)
        security_group.ingress_rules_complete = ingress_rules_complete
        mocked_client = mock.MagicMock()
        mocked_client.security_groups = {security_group.arn: security_group}
        mocked_client.is_failed_check.return_value = False
        with mock.patch.object(check_module, "ecs_client", mocked_client):
            return check_class().execute()[0]


@pytest.mark.parametrize("check_id,expected_ports,message", RUNTIME_PORT_CHECKS)
def test_incomplete_ingress_rules_require_manual_review(
    check_id, expected_ports, message
):
    result = _execute_check(check_id, [], ingress_rules_complete=False)

    assert result.status == "MANUAL"
    assert "ingress rules were not completely retrieved" in result.status_extended


def test_all_ports_check_only_fails_for_public_protocol_all_wildcard():
    check_id = "ecs_securitygroup_restrict_all_ports_internet"
    module_path = f"prowler.providers.alibabacloud.services.ecs.{check_id}.{check_id}"
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        check_module = importlib.import_module(module_path)
        check_class = getattr(check_module, check_id)
        failing_group = _security_group(
            "sg-fail-all",
            [
                {
                    "policy": "ACCEPT",
                    "ip_protocol": "ALL",
                    "ipv_6source_cidr_ip": "::/0",
                    "port_range": "-1/-1",
                }
            ],
        )
        passing_group = _security_group(
            "sg-pass-bounded",
            [
                {
                    "policy": "Accept",
                    "ip_protocol": "all",
                    "source_cidr_ip": "0.0.0.0/0",
                    "port_range": "20/22",
                }
            ],
        )
        mocked_client = mock.MagicMock()
        mocked_client.security_groups = {
            failing_group.arn: failing_group,
            passing_group.arn: passing_group,
        }
        _configure_failed_check_state(mocked_client)

        with mock.patch.object(check_module, "ecs_client", mocked_client):
            result = check_class().execute()

    assert len(result) == 2
    assert result[0].status == "FAIL"
    assert result[0].resource_id == "sg-fail-all"
    assert result[0].resource_arn == "arn:sg/sg-fail-all"
    assert result[0].region == "cn-hangzhou"
    assert "has all ports open" in result[0].status_extended
    assert "0.0.0.0/0 or ::/0" in result[0].status_extended
    assert mocked_client.set_failed_check.call_count == 1
    assert result[1].status == "PASS"
    assert result[1].resource_id == "sg-pass-bounded"
    assert "does not have all ports open" in result[1].status_extended


@pytest.mark.parametrize(
    "protocol,port_range",
    [
        ("all", "0/65535"),
        ("all", "1/65535"),
    ],
)
def test_all_ports_check_fails_for_every_full_range(protocol, port_range):
    result = _execute_check(
        "ecs_securitygroup_restrict_all_ports_internet",
        [
            {
                "policy": "Accept",
                "priority": 1,
                "ip_protocol": protocol,
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": port_range,
            }
        ],
    )

    assert result.status == "FAIL"


@pytest.mark.parametrize("port_range", ["0/65535", "1/65535"])
def test_tcp_full_range_fails_specialized_check_without_all_port_dedup(
    port_range,
):
    all_ports_check_id = "ecs_securitygroup_restrict_all_ports_internet"
    mysql_check_id = "ecs_securitygroup_restrict_mysql_internet"
    all_ports_module_path = f"prowler.providers.alibabacloud.services.ecs.{all_ports_check_id}.{all_ports_check_id}"
    mysql_module_path = (
        f"prowler.providers.alibabacloud.services.ecs.{mysql_check_id}.{mysql_check_id}"
    )
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        all_ports_module = importlib.import_module(all_ports_module_path)
        mysql_module = importlib.import_module(mysql_module_path)
        security_group = _security_group(
            "sg-tcp-full-range",
            [
                {
                    "policy": "Accept",
                    "priority": 1,
                    "ip_protocol": "tcp",
                    "source_cidr_ip": "0.0.0.0/0",
                    "port_range": port_range,
                }
            ],
        )
        mocked_client = mock.MagicMock()
        mocked_client.security_groups = {security_group.arn: security_group}
        _configure_failed_check_state(mocked_client)

        with (
            mock.patch.object(all_ports_module, "ecs_client", mocked_client),
            mock.patch.object(mysql_module, "ecs_client", mocked_client),
        ):
            all_ports_result = getattr(
                all_ports_module, all_ports_check_id
            )().execute()[0]
            mysql_result = getattr(mysql_module, mysql_check_id)().execute()[0]

    assert all_ports_result.status == "PASS"
    assert mysql_result.status == "FAIL"
    assert "MySQL TCP port 3306 open" in mysql_result.status_extended
    assert "was not checked" not in mysql_result.status_extended


def test_all_ports_check_requires_manual_review_for_incomplete_rules():
    result = _execute_check(
        "ecs_securitygroup_restrict_all_ports_internet",
        [],
        ingress_rules_complete=False,
    )

    assert result.status == "MANUAL"
    assert "ingress rules were not completely retrieved" in result.status_extended


def test_all_ports_failure_suppresses_redundant_specialized_failure():
    all_ports_check_id = "ecs_securitygroup_restrict_all_ports_internet"
    mysql_check_id = "ecs_securitygroup_restrict_mysql_internet"
    all_ports_module_path = f"prowler.providers.alibabacloud.services.ecs.{all_ports_check_id}.{all_ports_check_id}"
    mysql_module_path = (
        f"prowler.providers.alibabacloud.services.ecs.{mysql_check_id}.{mysql_check_id}"
    )
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_alibabacloud_provider(),
    ):
        all_ports_module = importlib.import_module(all_ports_module_path)
        mysql_module = importlib.import_module(mysql_module_path)
        security_group = _security_group(
            "sg-dedup",
            [
                {
                    "policy": "Accept",
                    "priority": 1,
                    "ip_protocol": "all",
                    "source_cidr_ip": "0.0.0.0/0",
                    "port_range": "-1/-1",
                }
            ],
        )
        mocked_client = mock.MagicMock()
        mocked_client.security_groups = {security_group.arn: security_group}
        _configure_failed_check_state(mocked_client)

        with (
            mock.patch.object(all_ports_module, "ecs_client", mocked_client),
            mock.patch.object(mysql_module, "ecs_client", mocked_client),
        ):
            all_ports_result = getattr(
                all_ports_module, all_ports_check_id
            )().execute()[0]
            mysql_result = getattr(mysql_module, mysql_check_id)().execute()[0]

    assert all_ports_result.status == "FAIL"
    assert mysql_result.status == "PASS"
    assert "was not checked" in mysql_result.status_extended
    assert "all-ports internet exposure check already failed" in (
        mysql_result.status_extended
    )
