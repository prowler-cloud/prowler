"""Tests for elbv2_listener_pqc_tls_enabled check."""

from unittest import mock

import pytest
from boto3 import client, resource
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_elbv2_listener_pqc_tls_enabled:
    """Test cases for the elbv2_listener_pqc_tls_enabled check."""

    def _create_alb_infrastructure(self, region=AWS_REGION_EU_WEST_1):
        """Helper to create VPC, subnets, security group, target group, and ALB.

        Returns a tuple of (elbv2_client, lb_response, target_group_arn).
        """
        conn = client("elbv2", region_name=region)
        ec2 = resource("ec2", region_name=region)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{region}a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{region}b",
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        response = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=8080,
            VpcId=vpc.id,
            HealthCheckProtocol="HTTP",
            HealthCheckPort="8080",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=5,
            HealthCheckTimeoutSeconds=3,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )
        target_group_arn = response["TargetGroups"][0]["TargetGroupArn"]

        return conn, lb, target_group_arn

    def _create_nlb_infrastructure(self, region=AWS_REGION_EU_WEST_1):
        """Helper to create VPC, subnets, target group, and NLB.

        Returns a tuple of (elbv2_client, lb_response, target_group_arn).
        """
        conn = client("elbv2", region_name=region)
        ec2 = resource("ec2", region_name=region)

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-nlb",
            Subnets=[subnet1.id, subnet2.id],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]

        response = conn.create_target_group(
            Name="a-target",
            Protocol="TCP",
            Port=8080,
            VpcId=vpc.id,
        )
        target_group_arn = response["TargetGroups"][0]["TargetGroupArn"]

        return conn, lb, target_group_arn

    def _mock_and_execute(self, audit_config=None):
        """Helper to set up mocks and execute the check.

        Must be called inside a @mock_aws decorated method, after AWS
        resources have been created with moto.
        """
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        audit_config = audit_config or {}
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            create_default_organization=False,
            audit_config=audit_config,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                    audit_config=audit_config,
                ),
            ),
            mock.patch(
                "prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled.elbv2_client",
                new=ELBv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled import (
                elbv2_listener_pqc_tls_enabled,
            )

            check = elbv2_listener_pqc_tls_enabled()
            return check.execute()

    def _assert_listener_arn_in_status(self, result, listener_arn):
        """Assert that remediation details identify the affected listener ARN."""
        assert listener_arn in result[0].status_extended

    # ------------------------------------------------------------------
    # No-resource scenarios
    # ------------------------------------------------------------------

    @mock_aws
    def test_no_load_balancers(self):
        """Test that no findings are returned when there are no load balancers."""
        result = self._mock_and_execute()
        assert len(result) == 0

    @mock_aws
    def test_lb_with_http_listener_only(self):
        """Test PASS when a load balancer has no HTTPS/TLS listeners."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == "ELBv2 my-lb has no HTTPS/TLS listeners."
        assert result[0].resource_id == "my-lb"

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "ssl_policy",
        [
            "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
        ],
    )
    @mock_aws
    def test_listener_with_pq_policy_pass(self, ssl_policy):
        """Test PASS when HTTPS listener uses an allowed PQ TLS policy."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy=ssl_policy,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has all HTTPS/TLS listeners using a post-quantum TLS policy."
        )
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_multiple_https_listeners_all_pq_pass(self):
        """Test PASS when a LB has multiple HTTPS listeners all using PQ policies."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=8443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has all HTTPS/TLS listeners using a post-quantum TLS policy."
        )
        assert result[0].resource_id == "my-lb"

    @mock_aws
    def test_mixed_http_and_pq_https_listeners_pass(self):
        """Test PASS when LB has both HTTP and HTTPS listeners, HTTPS using PQ policy."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        # HTTP listener (out of scope)
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )
        # HTTPS listener with PQ policy
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "my-lb"

    # ------------------------------------------------------------------
    # FAIL scenarios
    # ------------------------------------------------------------------

    @mock_aws
    def test_listener_with_classical_tls_policy_fail(self):
        """Test FAIL when HTTPS listener uses a classical (non-PQ) TLS policy."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        listener = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )["Listeners"][0]

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"ELBv2 my-lb has HTTPS/TLS listeners without post-quantum TLS policy: HTTPS:443 ({listener['ListenerArn']}) uses ELBSecurityPolicy-TLS13-1-2-2021-06."
        )
        self._assert_listener_arn_in_status(result, listener["ListenerArn"])
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_listener_with_empty_ssl_policy_fail(self):
        """Test FAIL when an HTTPS listener has no SSL policy value."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        listener = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )["Listeners"][0]

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            create_default_organization=False,
        )
        service = ELBv2(aws_provider)
        service.loadbalancersv2[lb["LoadBalancerArn"]].listeners[
            listener["ListenerArn"]
        ].ssl_policy = ""

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled.elbv2_client",
                new=service,
            ),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled import (
                elbv2_listener_pqc_tls_enabled,
            )

            result = elbv2_listener_pqc_tls_enabled().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"ELBv2 my-lb has HTTPS/TLS listeners without post-quantum TLS policy: HTTPS:443 ({listener['ListenerArn']}) uses <none>."
        )
        assert result[0].resource_id == "my-lb"

    @mock_aws
    def test_listener_with_legacy_policy_fail(self):
        """Test FAIL when HTTPS listener uses a legacy TLS policy."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        listener = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS-1-1-2017-01",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )["Listeners"][0]

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"ELBv2 my-lb has HTTPS/TLS listeners without post-quantum TLS policy: HTTPS:443 ({listener['ListenerArn']}) uses ELBSecurityPolicy-TLS-1-1-2017-01."
        )
        self._assert_listener_arn_in_status(result, listener["ListenerArn"])
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_mixed_pq_and_non_pq_listeners_fail(self):
        """Test FAIL when LB has one PQ listener and one non-PQ listener."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        # PQ listener
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )
        # Non-PQ listener
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=8443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "ELBSecurityPolicy-TLS13-1-2-2021-06" in result[0].status_extended
        assert result[0].resource_id == "my-lb"

    @mock_aws
    def test_multiple_non_pq_listeners_lists_all_policies_fail(self):
        """Test FAIL lists all non-PQ policies when multiple listeners are non-compliant."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS-1-1-2017-01",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=8443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        # Both non-PQ policies should be mentioned
        assert "ELBSecurityPolicy-TLS-1-1-2017-01" in result[0].status_extended
        assert "ELBSecurityPolicy-TLS13-1-2-2021-06" in result[0].status_extended
        assert result[0].resource_id == "my-lb"

    # ------------------------------------------------------------------
    # Custom audit_config scenario
    # ------------------------------------------------------------------

    @mock_aws
    def test_custom_audit_config_narrows_allowlist(self):
        """Test that a custom audit_config allowlist is honoured.

        When elbv2_listener_pqc_tls_allowed_policies is overridden to only
        allow FIPS PQ policies, a non-FIPS PQ policy should FAIL.
        """
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        # Use a PQ policy that is in the default list but NOT in our custom list
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        custom_config = {
            "elbv2_listener_pqc_tls_allowed_policies": [
                "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
                "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
            ]
        }

        result = self._mock_and_execute(audit_config=custom_config)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09" in result[0].status_extended

    @mock_aws
    def test_custom_audit_config_fips_policy_pass(self):
        """Test PASS when listener uses a FIPS PQ policy and custom config allows it."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        custom_config = {
            "elbv2_listener_pqc_tls_allowed_policies": [
                "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
                "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
            ]
        }

        result = self._mock_and_execute(audit_config=custom_config)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has all HTTPS/TLS listeners using a post-quantum TLS policy."
        )

    @pytest.mark.parametrize(
        "configured_policies",
        [
            None,
            [],
            123,
        ],
    )
    @mock_aws
    def test_malformed_audit_config_falls_back_to_defaults(self, configured_policies):
        """Test malformed allowlist values fall back to the built-in PQ policies."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        with mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled.logger.warning"
        ) as logger_warning:
            result = self._mock_and_execute(
                audit_config={
                    "elbv2_listener_pqc_tls_allowed_policies": configured_policies
                }
            )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "my-lb"
        assert any(
            "elbv2_listener_pqc_tls_allowed_policies" in call_args[0][0]
            for call_args in logger_warning.call_args_list
        )

    @mock_aws
    def test_tls_listener_with_pq_policy_pass(self):
        """Test PASS when a TLS listener uses an allowed PQ TLS policy."""
        conn, lb, target_group_arn = self._create_nlb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="TLS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "my-nlb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_nlb_with_tcp_listener_only(self):
        """Test PASS when an NLB has no HTTPS/TLS listeners."""
        conn, lb, target_group_arn = self._create_nlb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="TCP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == "ELBv2 my-nlb has no HTTPS/TLS listeners."
        assert result[0].resource_id == "my-nlb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_tls_listener_with_non_pq_policy_fail(self):
        """Test FAIL when a TLS listener uses a non-PQ TLS policy."""
        conn, lb, target_group_arn = self._create_nlb_infrastructure()
        listener = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="TLS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )["Listeners"][0]

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"ELBv2 my-nlb has HTTPS/TLS listeners without post-quantum TLS policy: TLS:443 ({listener['ListenerArn']}) uses ELBSecurityPolicy-TLS13-1-2-2021-06."
        )
        self._assert_listener_arn_in_status(result, listener["ListenerArn"])
        assert result[0].resource_id == "my-nlb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]

    @mock_aws
    def test_listener_discovery_failure_returns_fail(self):
        """Test FAIL when listeners cannot be retrieved for a load balancer."""
        conn, lb, _ = self._create_alb_infrastructure()

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            create_default_organization=False,
        )

        service = ELBv2(aws_provider)
        error = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "User is not authorized to perform: elasticloadbalancing:DescribeListeners",
                }
            },
            "DescribeListeners",
        )
        service.loadbalancersv2[lb["LoadBalancerArn"]].listeners = {}
        service.regional_clients[AWS_REGION_EU_WEST_1] = mock.MagicMock(
            region=AWS_REGION_EU_WEST_1,
            get_paginator=mock.MagicMock(side_effect=error),
        )
        service._describe_listeners(
            (lb["LoadBalancerArn"], service.loadbalancersv2[lb["LoadBalancerArn"]])
        )

        assert service.loadbalancersv2[lb["LoadBalancerArn"]].listener_discovery_failed

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled.elbv2_client",
                new=service,
            ),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_listener_pqc_tls_enabled.elbv2_listener_pqc_tls_enabled import (
                elbv2_listener_pqc_tls_enabled,
            )

            result = elbv2_listener_pqc_tls_enabled().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]
        assert "could not retrieve listeners" in result[0].status_extended
        assert (
            "post-quantum TLS policy compliance cannot be determined"
            in result[0].status_extended
        )
