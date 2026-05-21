"""Tests for elbv2_listener_pqc_tls_enabled check."""

from unittest import mock

import pytest
from boto3 import client, resource
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

    def _mock_and_execute(self):
        """Helper to set up mocks and execute the check.

        Must be called inside a @mock_aws decorated method, after AWS
        resources have been created with moto.
        """
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            create_default_organization=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(
                    [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
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

    def _mock_and_execute_with_audit_config(self, audit_config):
        """Helper to set up mocks with custom audit_config and execute the check."""
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

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
        """Test that HTTP-only listeners are skipped (no findings)."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()
        assert len(result) == 0

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "ssl_policy",
        [
            "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
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
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has HTTPS/TLS listeners without post-quantum TLS policy (ELBSecurityPolicy-TLS13-1-2-2021-06)."
        )
        assert result[0].resource_id == "my-lb"
        assert result[0].resource_arn == lb["LoadBalancerArn"]
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_listener_with_legacy_policy_fail(self):
        """Test FAIL when HTTPS listener uses a legacy TLS policy."""
        conn, lb, target_group_arn = self._create_alb_infrastructure()
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=443,
            SslPolicy="ELBSecurityPolicy-TLS-1-1-2017-01",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        result = self._mock_and_execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has HTTPS/TLS listeners without post-quantum TLS policy (ELBSecurityPolicy-TLS-1-1-2017-01)."
        )
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

        result = self._mock_and_execute_with_audit_config(custom_config)

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

        result = self._mock_and_execute_with_audit_config(custom_config)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "ELBv2 my-lb has all HTTPS/TLS listeners using a post-quantum TLS policy."
        )
