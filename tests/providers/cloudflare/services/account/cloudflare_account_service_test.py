from datetime import datetime, timezone
from types import SimpleNamespace

from prowler.providers.cloudflare.services.account.account_service import (
    SUPER_ADMIN_ROLE_NAME,
    Account,
    CloudflareAccountMember,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)

ISSUED = datetime(2026, 1, 1, tzinfo=timezone.utc)
OTHER_ACCOUNT = "other-account-id"


def _policy(resources, effect="allow"):
    return SimpleNamespace(effect=effect, resources=resources)


class _Paginator:
    """Fake SDK paginator exposing iter_pages(), optionally failing on a page."""

    def __init__(self, pages, fail_at=None):
        self.pages, self.fail_at = pages, fail_at

    def iter_pages(self):
        for index, page in enumerate(self.pages):
            if index == self.fail_at:
                raise Exception("page request failed")
            yield SimpleNamespace(result=page)


def _token(token_id, **kwargs):
    defaults = dict(
        id=token_id,
        name=f"name-{token_id}",
        status="active",
        condition=None,
        issued_on=ISSUED,
        expires_on=None,
        last_used_on=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _provider():
    provider = set_mocked_cloudflare_provider()
    client = provider.session.client
    client.accounts.get.return_value = SimpleNamespace(
        id=ACCOUNT_ID,
        name=ACCOUNT_NAME,
        settings=SimpleNamespace(enforce_twofactor=True),
    )
    client.accounts.members.list.return_value = [
        SimpleNamespace(
            id="m1",
            status="accepted",
            user=SimpleNamespace(
                email="admin@example.com", two_factor_authentication_enabled=True
            ),
            roles=[SimpleNamespace(name=SUPER_ADMIN_ROLE_NAME)],
            policies=None,
        ),
        SimpleNamespace(
            id="m2",
            status="accepted",
            user=SimpleNamespace(
                email="dev@example.com", two_factor_authentication_enabled=False
            ),
            roles=None,
            policies=[
                SimpleNamespace(
                    access="allow",
                    permission_groups=[SimpleNamespace(name="Workers Admin")],
                ),
                SimpleNamespace(
                    access="deny",
                    permission_groups=[SimpleNamespace(name=SUPER_ADMIN_ROLE_NAME)],
                ),
                SimpleNamespace(
                    access=None,
                    permission_groups=[SimpleNamespace(name="DNS")],
                ),
            ],
        ),
        # repeated page: the listing must stop here
        SimpleNamespace(id="m1", status="accepted", user=None, roles=None),
        SimpleNamespace(
            id="m3",
            status="accepted",
            user=SimpleNamespace(
                email="late@example.com", two_factor_authentication_enabled=True
            ),
            roles=None,
            policies=None,
        ),
    ]
    request_ip = SimpleNamespace(in_=["192.0.2.0/24"], not_in=None)
    client.accounts.tokens.list.return_value = [
        _token("acct-1", condition=SimpleNamespace(request_ip=request_ip))
    ]
    account_policy = [_policy({f"com.cloudflare.api.account.{ACCOUNT_ID}": "*"})]
    client.user.tokens.list.return_value = [
        _token("user-1", policies=account_policy),
        # duplicate entries are skipped
        _token("user-1", policies=account_policy),
        # only grants access to an account that is not audited: not reported
        _token(
            "user-2",
            policies=[_policy({f"com.cloudflare.api.account.{OTHER_ACCOUNT}": "*"})],
        ),
    ]
    return provider


class TestAccountService:
    def test_service(self):
        service = Account(_provider())

        assert service.service == "account"
        assert len(service.accounts) == 1
        assert service.accounts[0].id == ACCOUNT_ID
        assert service.accounts[0].account_id == ACCOUNT_ID
        assert service.accounts[0].name == ACCOUNT_NAME
        assert service.accounts[0].enforce_twofactor is True

        # the duplicate m1 entry is skipped, later members are still read
        assert [m.id for m in service.members] == ["m1", "m2", "m3"]
        admin, dev, _ = service.members
        assert admin.name == "admin@example.com"
        assert admin.account_id == ACCOUNT_ID
        assert admin.two_factor_enabled is True
        assert admin.is_super_admin is True
        assert dev.two_factor_enabled is False
        # deny policies must not grant roles; policies without access do
        assert dev.roles == ["DNS", "Workers Admin"]
        assert dev.is_super_admin is False

        assert [(t.id, t.owner) for t in service.tokens] == [
            ("acct-1", "account"),
            ("user-1", "user"),
        ]
        account_token, user_token = service.tokens
        assert account_token.account_id == ACCOUNT_ID
        assert account_token.ip_allow_list == ["192.0.2.0/24"]
        assert account_token.ip_deny_list == []
        # user tokens are attributed to the audited account their policy grants
        assert user_token.account_id == ACCOUNT_ID
        assert user_token.ip_allow_list == []
        assert user_token.unique_name == "name-user-1 (user-1)"

    def test_errors_are_handled(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        client.accounts.get.side_effect = Exception("boom")
        client.accounts.members.list.side_effect = Exception("boom")
        client.accounts.tokens.list.side_effect = Exception("forbidden")
        client.user.tokens.list.side_effect = Exception("forbidden")

        service = Account(provider)

        assert service.accounts == []
        assert service.members == []
        assert service.tokens == []
        assert service.settings_failed_accounts == {ACCOUNT_ID}
        assert service.members_failed_accounts == {ACCOUNT_ID}
        assert service.members_listed_accounts == set()
        assert service.tokens_failed_accounts == {ACCOUNT_ID}

    def test_failure_on_later_page_discards_partial_lists(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        member = SimpleNamespace(id="m1", status="accepted", user=None, roles=None)
        client.accounts.members.list.return_value = _Paginator(
            [[member], [SimpleNamespace(id="m2")]], fail_at=1
        )
        client.accounts.tokens.list.return_value = _Paginator(
            [[_token("t1")], [_token("t2")]], fail_at=1
        )
        client.user.tokens.list.return_value = []

        service = Account(provider)

        assert service.members == []
        assert service.members_failed_accounts == {ACCOUNT_ID}
        assert service.tokens == []
        assert service.tokens_failed_accounts == {ACCOUNT_ID}

    def test_repeated_page_stops_listing(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        page = [SimpleNamespace(id="m1", status="accepted", user=None, roles=None)]
        # an API ignoring the page parameter would return the same page forever
        client.accounts.members.list.return_value = _Paginator([page] * 50)
        client.accounts.tokens.list.return_value = []
        client.user.tokens.list.return_value = []

        service = Account(provider)

        assert [m.id for m in service.members] == ["m1"]
        assert service.members_listed_accounts == {ACCOUNT_ID}

    def test_user_token_scoping(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        client.accounts.members.list.return_value = []
        client.accounts.tokens.list.return_value = []
        client.zones.list.return_value = [
            SimpleNamespace(id="zone-1", account=SimpleNamespace(id=ACCOUNT_ID)),
            SimpleNamespace(id="zone-2", account=SimpleNamespace(id=OTHER_ACCOUNT)),
        ]
        client.user.tokens.list.return_value = [
            _token("all", policies=[_policy({"com.cloudflare.api.account.*": "*"})]),
            _token(
                "zone-mine",
                policies=[_policy({"com.cloudflare.api.account.zone.zone-1": "*"})],
            ),
            _token(
                "zone-other",
                policies=[_policy({"com.cloudflare.api.account.zone.zone-2": "*"})],
            ),
            _token(
                "nested",
                policies=[
                    _policy(
                        {
                            f"com.cloudflare.api.account.{ACCOUNT_ID}": {
                                "com.cloudflare.api.account.zone.*": "*"
                            }
                        }
                    )
                ],
            ),
            _token(
                "denied",
                policies=[
                    _policy(
                        {f"com.cloudflare.api.account.{ACCOUNT_ID}": "*"}, effect="deny"
                    )
                ],
            ),
            _token("no-policies", policies=None),
        ]

        service = Account(provider)

        assert [t.id for t in service.tokens] == ["all", "zone-mine", "nested"]
        assert {t.account_id for t in service.tokens} == {ACCOUNT_ID}
        assert service.user_tokens_unattributed_accounts == set()

    def test_nested_zone_wildcard_is_limited_to_parent_account(self):
        provider = set_mocked_cloudflare_provider()
        provider.identity.audited_accounts = [ACCOUNT_ID, OTHER_ACCOUNT]
        client = provider.session.client
        client.accounts.get.side_effect = Exception("not needed")
        client.accounts.members.list.return_value = []
        client.accounts.tokens.list.return_value = []
        client.user.tokens.list.return_value = [
            _token(
                "nested-other",
                policies=[
                    _policy(
                        {
                            f"com.cloudflare.api.account.{OTHER_ACCOUNT}": {
                                "com.cloudflare.api.account.zone.*": "*"
                            }
                        }
                    )
                ],
            )
        ]

        service = Account(provider)

        # only the parent account, not every audited account
        assert [(t.id, t.account_id) for t in service.tokens] == [
            ("nested-other", OTHER_ACCOUNT)
        ]

    def test_zone_lookup_failure_marks_user_tokens_unattributed(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        client.accounts.members.list.return_value = []
        client.accounts.tokens.list.return_value = []
        client.zones.list.side_effect = Exception("zones forbidden")
        client.user.tokens.list.return_value = [
            _token(
                "zone-token",
                policies=[_policy({"com.cloudflare.api.account.zone.zone-1": "*"})],
            )
        ]

        service = Account(provider)

        assert service.tokens == []
        assert service.user_tokens_unattributed_accounts == {ACCOUNT_ID}

    def test_member_model_defaults(self):
        member = CloudflareAccountMember(id="m", name="m", account_id=ACCOUNT_ID)
        assert member.roles == []
        assert member.is_super_admin is False
        assert member.two_factor_enabled is None


class TestGlobalRegion:
    def test_account_scoped_findings_report_global_region(self):
        from prowler.lib.check.models import CheckReportCloudflare
        from prowler.providers.cloudflare.services.dns.dns_service import (
            CloudflareDNSRecord,
        )

        metadata = (
            '{"Provider": "cloudflare", "CheckID": "account_t", "CheckTitle": "t", '
            '"CheckType": [], "ServiceName": "account", "SubServiceName": "", '
            '"ResourceIdTemplate": "", "Severity": "low", "ResourceType": "x", '
            '"Description": "d", "Risk": "r", "RelatedUrl": "", "Remediation": '
            '{"Code": {"CLI": "", "NativeIaC": "", "Other": "", "Terraform": ""}, '
            '"Recommendation": {"Text": "", "Url": ""}}, "Categories": [], '
            '"DependsOn": [], "RelatedTo": [], "Notes": ""}'
        )
        member = CloudflareAccountMember(
            id="m", name="user@example.com", account_id=ACCOUNT_ID
        )
        report = CheckReportCloudflare(metadata=metadata, resource=member)
        # the member's email must not be used as the region
        assert report.zone_name == "global"
        assert report.region == "global"

        # zone-scoped resources keep their zone as region
        record = CloudflareDNSRecord(
            id="r", zone_id="z", zone_name="example.com", name="www.example.com"
        )
        assert (
            CheckReportCloudflare(metadata=metadata, resource=record).zone_name
            == "example.com"
        )
