from unittest.mock import MagicMock

from prowler.providers.huaweicloud.lib.mutelist.mutelist import HuaweiCloudMutelist

ACCOUNT_ID = "123456789012"


def _finding(
    check_id="obs_bucket_encryption",
    region="cn-north-4",
    resource_id="bucket-1",
    tags=None,
):
    finding = MagicMock()
    finding.check_metadata = MagicMock()
    finding.check_metadata.CheckID = check_id
    finding.region = region
    finding.resource_id = resource_id
    finding.resource_tags = tags or []
    return finding


class TestHuaweiCloudMutelist:
    def test_empty_mutelist_not_muted(self):
        mutelist = HuaweiCloudMutelist(mutelist_content={}, account_id=ACCOUNT_ID)
        assert not mutelist.is_finding_muted(_finding(), ACCOUNT_ID)

    def test_matching_finding_is_muted(self):
        content = {
            "Accounts": {
                ACCOUNT_ID: {
                    "Checks": {
                        "obs_bucket_encryption": {
                            "Regions": ["*"],
                            "Resources": ["bucket-1"],
                        }
                    }
                }
            }
        }
        mutelist = HuaweiCloudMutelist(mutelist_content=content, account_id=ACCOUNT_ID)
        assert mutelist.is_finding_muted(_finding(), ACCOUNT_ID)

    def test_non_matching_resource_not_muted(self):
        content = {
            "Accounts": {
                ACCOUNT_ID: {
                    "Checks": {
                        "obs_bucket_encryption": {
                            "Regions": ["*"],
                            "Resources": ["other-bucket"],
                        }
                    }
                }
            }
        }
        mutelist = HuaweiCloudMutelist(mutelist_content=content, account_id=ACCOUNT_ID)
        assert not mutelist.is_finding_muted(_finding(), ACCOUNT_ID)

    def test_wildcard_account_and_check_mutes(self):
        content = {
            "Accounts": {"*": {"Checks": {"*": {"Regions": ["*"], "Resources": ["*"]}}}}
        }
        mutelist = HuaweiCloudMutelist(mutelist_content=content, account_id=ACCOUNT_ID)
        assert mutelist.is_finding_muted(_finding(), ACCOUNT_ID)

    def test_region_filter_excludes(self):
        content = {
            "Accounts": {
                ACCOUNT_ID: {
                    "Checks": {
                        "obs_bucket_encryption": {
                            "Regions": ["cn-east-3"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }
        mutelist = HuaweiCloudMutelist(mutelist_content=content, account_id=ACCOUNT_ID)
        assert not mutelist.is_finding_muted(_finding(region="cn-north-4"), ACCOUNT_ID)

    def test_exception_resource_not_muted(self):
        content = {
            "Accounts": {
                ACCOUNT_ID: {
                    "Checks": {
                        "obs_bucket_encryption": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Exceptions": {"Resources": ["bucket-1"]},
                        }
                    }
                }
            }
        }
        mutelist = HuaweiCloudMutelist(mutelist_content=content, account_id=ACCOUNT_ID)
        assert not mutelist.is_finding_muted(
            _finding(resource_id="bucket-1"), ACCOUNT_ID
        )
