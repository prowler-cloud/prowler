from prowler.lib.scan_filters.scan_filters import is_resource_filtered


class Test_Scan_Filters:
    def test_is_resource_filtered(self):
        audit_resources = [
            "arn:aws:iam::123456789012:user/test_user",
            "arn:aws:s3:::test_bucket",
        ]
        assert is_resource_filtered(
            "arn:aws:iam::123456789012:user/test_user", audit_resources
        )
        assert not is_resource_filtered(
            "arn:aws:iam::123456789012:user/test1", audit_resources
        )
        assert is_resource_filtered("test_bucket", audit_resources)
        assert is_resource_filtered("arn:aws:s3:::test_bucket", audit_resources)
