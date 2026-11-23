from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID
from tests.providers.cloudflare.services.r2.cloudflare_r2_check_helpers import (
    BUCKET,
    make_bucket,
    run_r2_check,
)

CHECK = "r2_bucket_public_dev_url_disabled"


class Test_r2_bucket_public_dev_url_disabled:

    def test_retrieval_failed_one_account_manual(self):
        result = run_r2_check(
            CHECK, [make_bucket(), make_bucket()], failed=[ACCOUNT_ID]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].region == "global"
        assert "Workers R2 Storage Read" in result[0].status_extended

    def test_listing_failed_manual(self):
        result = run_r2_check(CHECK, [], list_failed=[ACCOUNT_ID])
        assert [r.status for r in result] == ["MANUAL"]

    def test_no_buckets(self):
        assert run_r2_check(CHECK, []) == []

    def test_unknown_skipped(self):
        assert run_r2_check(CHECK, [make_bucket()]) == []

    def test_pass(self):
        result = run_r2_check(CHECK, [make_bucket(public_dev_url_enabled=False)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == f"{ACCOUNT_ID}/default/{BUCKET}"
        assert result[0].resource_name == BUCKET
        assert result[0].account_id == ACCOUNT_ID
        assert result[0].region == "global"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} has public r2.dev access disabled."
        )

    def test_same_name_in_two_jurisdictions_is_distinct(self):
        result = run_r2_check(
            CHECK,
            [
                make_bucket(public_dev_url_enabled=False),
                make_bucket(public_dev_url_enabled=False, jurisdiction="eu"),
            ],
        )
        assert [r.resource_name for r in result] == [BUCKET, f"eu/{BUCKET}"]
        assert result[1].status_extended == (
            f"R2 bucket eu/{BUCKET} has public r2.dev access disabled."
        )

    def test_fail(self):
        result = run_r2_check(
            CHECK,
            [make_bucket(public_dev_url_enabled=True, public_dev_url="pub-x.r2.dev")],
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} is publicly readable through its r2.dev URL (pub-x.r2.dev)."
        )
