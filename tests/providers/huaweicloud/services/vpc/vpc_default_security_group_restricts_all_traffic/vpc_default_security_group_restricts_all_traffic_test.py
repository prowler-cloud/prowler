from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVpcDefaultSecurityGroupRestrictsAllTraffic:
    def _run_check(self, security_groups):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )

            vpc_client.security_groups = {sg.id: sg for sg in security_groups}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            return check.execute()

    def test_sg_with_open_ingress_fails(self):
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            remote_ip_prefix="0.0.0.0/0",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="default",
            region="la-south-2",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "ingress" in result[0].status_extended
        assert "open to any source" in result[0].status_extended

    def test_sg_with_open_egress_fails(self):
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="egress",
            protocol="tcp",
            ethertype="IPv4",
            remote_ip_prefix="::/0",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="default",
            region="la-south-2",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "egress" in result[0].status_extended

    def test_sg_with_empty_source_fields_fails(self):
        """Both remote_ip_prefix and remote_group_id empty means "any source"."""
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="egress",
            protocol="",
            ethertype="IPv4",
            remote_ip_prefix="",
            remote_group_id="",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="Sys-default",
            region="eu-west-101",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "egress" in result[0].status_extended

    def test_sg_with_remote_group_reference_passes(self):
        """A rule with empty remote_ip_prefix but a remote_group_id is NOT open."""
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="",
            ethertype="IPv4",
            remote_ip_prefix="",
            remote_group_id="sg-1",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="default",
            region="la-south-2",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_sg_restricted_passes(self):
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            remote_ip_prefix="10.0.0.0/24",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="default",
            region="la-south-2",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "does not have any rule open to any source" in result[0].status_extended

    def test_europe_default_sg_name_matched(self):
        """The Europe cloud names the auto-created SG 'Sys-default'."""
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            remote_ip_prefix="0.0.0.0/0",
        )
        sg = SecurityGroups(
            id="sg-1",
            name="Sys-default",
            region="eu-west-101",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_non_default_sg_ignored(self):
        """SGs not named default/Sys-default are ignored by this check."""
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroupRule,
            SecurityGroups,
        )

        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            remote_ip_prefix="0.0.0.0/0",
        )
        sg = SecurityGroups(
            id="sg-custom",
            name="my-custom-sg",
            region="la-south-2",
            rules=[rule],
        )

        result = self._run_check([sg])

        assert len(result) == 0

    def test_sg_empty_name_skipped(self):
        from prowler.providers.huaweicloud.services.vpc.vpc_service import (
            SecurityGroups,
        )

        sg = SecurityGroups(
            id="sg-1",
            name="",
            region="la-south-2",
            rules=[],
        )

        result = self._run_check([sg])

        assert len(result) == 0

    def test_no_security_groups(self):
        result = self._run_check([])
        assert len(result) == 0
