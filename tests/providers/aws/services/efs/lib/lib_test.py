from prowler.providers.aws.services.efs.lib.lib import is_public_access_allowed


class Test_EFS_lib:
    def test__is_public_access_allowed__(self):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
        }
        assert is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_principal_dict(self):
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
        }
        assert is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_secure_conditions(self):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
            "Condition": {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}},
        }
        assert not is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_secure_conditions_and_allowed_conditions(
        self,
    ):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
            "Condition": {
                "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                "StringEquals": {"aws:SourceOwner": "123456789012"},
            },
        }
        assert not is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_secure_conditions_and_allowed_conditions_nested(
        self,
    ):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
            "Condition": {
                "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                "StringEquals": {"aws:SourceOwner": "123456789012"},
                "StringEqualsIfExists": {"aws:SourceVpce": "vpce-1234567890abcdef0"},
            },
        }
        assert not is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_secure_conditions_and_allowed_conditions_nested_dict(
        self,
    ):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
            "Condition": {
                "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                "StringEquals": {"aws:SourceOwner": "123456789012"},
                "StringEqualsIfExists": {
                    "aws:SourceVpce": {
                        "vpce-1234567890abcdef0": "vpce-1234567890abcdef0"
                    }
                },
            },
        }
        assert not is_public_access_allowed(statement)

    def test__is_public_access_allowed__with_secure_conditions_and_allowed_conditions_nested_dict_key(
        self,
    ):
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "elasticfilesystem:ClientMount",
            "Resource": "*",
            "Condition": {
                "Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"},
                "StringEquals": {"aws:SourceOwner": "123456789012"},
                "StringEqualsIfExists": {
                    "aws:SourceVpce": {
                        "vpce-1234567890abcdef0": "vpce-1234567890abcdef0"
                    }
                },
            },
        }
        assert not is_public_access_allowed(statement)
