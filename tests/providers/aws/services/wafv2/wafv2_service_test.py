from unittest.mock import patch

import botocore
from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

PAGED_ACL_FIRST_NAME = "paged-web-acl-1"
PAGED_ACL_SECOND_NAME = "paged-web-acl-2"
PAGED_ACL_FIRST_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/paged-web-acl-1"
)
PAGED_ACL_SECOND_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/paged-web-acl-2"
)


def mock_make_api_call_list_web_acls_paginated(self, operation_name, kwarg):
    """Serve ListWebACLs across two pages, keyed off NextMarker so no state is shared.

    Page one carries a marker; page two carries none. Both pages return a Web ACL, so a
    collector that reads only the first response sees half the inventory.
    """
    if operation_name == "ListWebACLs":
        if not kwarg.get("NextMarker"):
            return {
                "WebACLs": [
                    {
                        "Name": PAGED_ACL_FIRST_NAME,
                        "Id": "paged-1",
                        "ARN": PAGED_ACL_FIRST_ARN,
                    }
                ],
                "NextMarker": "page-two",
            }
        return {
            "WebACLs": [
                {
                    "Name": PAGED_ACL_SECOND_NAME,
                    "Id": "paged-2",
                    "ARN": PAGED_ACL_SECOND_ARN,
                }
            ]
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_list_web_acls_empty_page_with_marker(
    self, operation_name, kwarg
):
    """Serve an empty middle page that still carries a NextMarker.

    WAFv2 returns a marker even when a page held everything, so an empty page is the only
    reliable stop. Page one holds a Web ACL and a marker, page two is empty and still carries
    a marker, page three holds a second Web ACL. A collector that stops on the empty page
    reports one Web ACL; one that trusts the marker alone walks on and reports two.
    """
    if operation_name == "ListWebACLs":
        marker = kwarg.get("NextMarker")
        if not marker:
            return {
                "WebACLs": [
                    {
                        "Name": PAGED_ACL_FIRST_NAME,
                        "Id": "paged-1",
                        "ARN": PAGED_ACL_FIRST_ARN,
                    }
                ],
                "NextMarker": "page-two",
            }
        if marker == "page-two":
            return {"WebACLs": [], "NextMarker": "page-three"}
        return {
            "WebACLs": [
                {
                    "Name": PAGED_ACL_SECOND_NAME,
                    "Id": "paged-2",
                    "ARN": PAGED_ACL_SECOND_ARN,
                }
            ]
        }
    return orig(self, operation_name, kwarg)


class ScriptedListWebACLs:
    """A stand-in WAFv2 client that serves a scripted ListWebACLs page sequence.

    moto cannot be driven to a thousand pages, and the paginator's page cap is a local rather
    than a module constant so it cannot be lowered for a test, so a scripted client is the only
    way to reach the cap at all. It costs nothing: the pages are plain dicts built in a list
    comprehension and neither test below takes a measurable fraction of a second.
    """

    def __init__(self, pages: list):
        """Take the pages to serve in order, and start the call counter at zero."""
        self.pages = pages
        self.calls = 0

    def list_web_acls(self, **kwargs):
        """Return the next scripted page, or an empty one once the script runs out."""
        index = self.calls
        self.calls += 1
        return self.pages[index] if index < len(self.pages) else {"WebACLs": []}


def _paged_acl(index: int) -> dict:
    """Build one ListWebACLs summary entry."""
    return {
        "ARN": f"arn:aws:wafv2:us-east-1:123456789012:regional/webacl/paged-{index}",
        "Name": f"paged-{index}",
        "Id": f"paged-{index}",
    }


def mock_make_api_call_list_web_acls_infinite_loop(self, operation_name, kwarg):
    """Return the same NextMarker forever to test the loop guard.

    Every ListWebACLs call returns one Web ACL and the marker "loop-forever". A paginator
    without a seen-set guard would spin indefinitely; one with the guard detects the
    repeated marker, logs an error, and terminates.
    """
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {
                    "Name": PAGED_ACL_FIRST_NAME,
                    "Id": "paged-1",
                    "ARN": PAGED_ACL_FIRST_ARN,
                }
            ],
            "NextMarker": "loop-forever",
        }
    return orig(self, operation_name, kwarg)


class Test_WAFv2_Service:
    # Test WAFv2 Service
    @mock_aws
    def test_service(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.service == "wafv2"

    # Test WAFv2 Client
    @mock_aws
    def test_client(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        for regional_client in wafv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFV2"

    # Test WAFv2 Session
    @mock_aws
    def test__get_session__(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.session.__class__.__name__ == "Session"

    # Test WAFv2 Describe Regional Web ACLs
    @mock_aws
    def test_list_web_acls_regional(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_EU_WEST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # Test WAFv2 Describe Global Web ACLs
    @mock_aws
    def test_list_web_acls_global(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2.create_web_acl(
            Scope="CLOUDFRONT",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # A single ListWebACLs call returns at most 100 Web ACLs. The documented contract
    # states NextMarker signals more objects remain, so the paginator must follow it.
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_web_acls_paginated,
    )
    @mock_aws
    def test_list_web_acls_follows_next_marker(self):
        """Pagination across two pages collects both Web ACLs."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws_provider)

        assert len(wafv2.web_acls) == 2
        assert PAGED_ACL_FIRST_ARN in wafv2.web_acls
        assert PAGED_ACL_SECOND_ARN in wafv2.web_acls
        assert wafv2.web_acls[PAGED_ACL_FIRST_ARN].name == PAGED_ACL_FIRST_NAME
        assert wafv2.web_acls[PAGED_ACL_SECOND_ARN].name == PAGED_ACL_SECOND_NAME

    # An empty middle page must not terminate collection when NextMarker points to more data.
    # The documented contract states the marker signals more objects remain, so an empty page
    # with a marker indicates the API will return data on the next call.
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_web_acls_empty_page_with_marker,
    )
    @mock_aws
    def test_list_web_acls_continues_past_an_empty_page_when_a_marker_remains(self):
        """Pagination continues through an empty middle page to collect all Web ACLs."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws_provider)

        assert len(wafv2.web_acls) == 2
        assert PAGED_ACL_FIRST_ARN in wafv2.web_acls
        assert PAGED_ACL_SECOND_ARN in wafv2.web_acls

    # The seen-set guard must terminate on a repeating marker without hanging. A marker that
    # never clears would spin indefinitely without this protection.
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_web_acls_infinite_loop,
    )
    @mock_aws
    def test_list_web_acls_terminates_on_repeating_marker(self):
        """Pagination detects and breaks on a marker that repeats forever."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Patch logger to verify error is logged
        with patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.logger"
        ) as mock_logger:
            wafv2 = WAFv2(aws_provider)

            # Service must terminate (not hang)
            assert len(wafv2.web_acls) == 1
            assert PAGED_ACL_FIRST_ARN in wafv2.web_acls

            # Loop detection must log an error for both CLOUDFRONT and REGIONAL scopes
            assert mock_logger.error.call_count >= 2
            error_messages = [call[0][0] for call in mock_logger.error.call_args_list]
            pagination_errors = [
                msg for msg in error_messages if "pagination loop detected" in msg
            ]
            assert len(pagination_errors) >= 2
            assert any(
                "loop-forever" in msg and "CLOUDFRONT" in msg
                for msg in pagination_errors
            )
            assert any(
                "loop-forever" in msg and "REGIONAL" in msg for msg in pagination_errors
            )
            # The repeating marker stops collection well below the page cap, so the cap's own
            # warning must stay silent: gating it on the marker alone would report truncation
            # here, on top of the loop-detected error that already names the real cause.
            assert sum("hit the 1000-page cap" in msg for msg in error_messages) == 0

    # The cap warning is gated on a pending marker, not on the iteration count alone, because
    # `iterations` reaches the cap on the final pass whether or not that pass finished the scan.
    @mock_aws
    def test_pagination_cap_is_silent_when_the_last_page_completes_the_scan(self):
        """A scope whose 1000th page carries no NextMarker is complete, so nothing is logged.

        Warning here would tell an operator their inventory may be truncated when every Web ACL
        was collected, which is the false positive the marker condition exists to prevent.
        """
        pages = [
            {"WebACLs": [_paged_acl(i)], "NextMarker": f"m{i}"} for i in range(999)
        ] + [{"WebACLs": [_paged_acl(999)]}]
        scripted = ScriptedListWebACLs(pages)
        wafv2 = WAFv2(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        with patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.logger"
        ) as mock_logger:
            collected = list(wafv2._paginate_web_acls(scripted, "REGIONAL"))

        assert len(collected) == 1000
        assert scripted.calls == 1000
        assert mock_logger.error.call_count == 0

    @mock_aws
    def test_pagination_cap_warns_when_a_marker_is_still_pending(self):
        """A scope still handing back a marker at the cap is truncated, so it must be logged.

        The paginator stops at the cap rather than following the marker forever, so the Web ACLs
        beyond it are genuinely missing from the scan and silence would hide that.
        """
        pages = [
            {"WebACLs": [_paged_acl(i)], "NextMarker": f"m{i}"} for i in range(1100)
        ]
        scripted = ScriptedListWebACLs(pages)
        wafv2 = WAFv2(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        with patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.logger"
        ) as mock_logger:
            collected = list(wafv2._paginate_web_acls(scripted, "REGIONAL"))

        assert len(collected) == 1000
        assert scripted.calls == 1000
        assert mock_logger.error.call_count == 1
        assert "hit the 1000-page cap" in mock_logger.error.call_args[0][0]

    @mock_aws
    def test_a_repeated_marker_on_the_final_entry_reports_only_the_loop(self):
        """A repeated marker seen on the 1000th loop entry must not also report the page cap.

        This is the one input where the two exits are indistinguishable by counter: the entry
        increments iterations to the cap BEFORE the repeated-marker guard breaks, and it leaves
        next_marker truthy, so a cap test written as `iterations >= max_iterations and next_marker`
        fires as well. The operator then gets two contradictory causes for one stop, and the cap
        message is the false one -- only 999 calls were made, and nothing was truncated by the cap.

        The 999th page hands back a marker already seen, which is what makes the 1000th entry break
        on the guard rather than on a completed enumeration.
        """
        pages = [
            {"WebACLs": [_paged_acl(i)], "NextMarker": f"m{i}"} for i in range(998)
        ] + [{"WebACLs": [_paged_acl(998)], "NextMarker": "m0"}]
        scripted = ScriptedListWebACLs(pages)
        wafv2 = WAFv2(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        with patch(
            "prowler.providers.aws.services.wafv2.wafv2_service.logger"
        ) as mock_logger:
            collected = list(wafv2._paginate_web_acls(scripted, "REGIONAL"))

        assert len(collected) == 999
        assert scripted.calls == 999
        assert mock_logger.error.call_count == 1
        assert "pagination loop detected" in mock_logger.error.call_args[0][0]
        assert "page cap" not in mock_logger.error.call_args[0][0]

    # Test WAFv2 Describe Web ACLs Resources
    @mock_aws
    def test_list_resources_for_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=lb["LoadBalancerArn"])
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        wafv2.web_acls[waf_arn].albs.append(lb["LoadBalancerArn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].albs) == 1
        assert lb["LoadBalancerArn"] in wafv2.web_acls[waf_arn].albs

    # Test WAFv2 describe Web user pools
    @mock_aws
    def test_list_resources_for_web_user_pools(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        cognito = client("cognito-idp", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        user_pool = cognito.create_user_pool(PoolName="my-user-pool")["UserPool"]
        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=user_pool["Arn"])
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        wafv2.web_acls[waf_arn].user_pools.append(user_pool["Arn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].user_pools) == 1
        assert user_pool["Arn"] in wafv2.web_acls[waf_arn].user_pools

    @mock_aws
    def test_list_tags(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        wafv2.tag_resource(
            ResourceARN=waf["ARN"], Tags=[{"Key": "Name", "Value": "my-web-acl"}]
        )
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].tags) == 1
        assert wafv2.web_acls[waf_arn].tags[0]["Key"] == "Name"
        assert wafv2.web_acls[waf_arn].tags[0]["Value"] == "my-web-acl"

    @mock_aws
    def test_get_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rule-on",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]

        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].rules) == 1
        assert wafv2.web_acls[waf_arn].rules[0].name == "rule-on"
        assert wafv2.web_acls[waf_arn].rules[0].cloudwatch_metrics_enabled
