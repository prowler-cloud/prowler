from config.cloudfoundry import (
    build_django_databases_from_vcap_services,
    get_allowed_hosts_from_vcap_application,
    get_cors_origins_from_vcap_application,
    get_database_settings_from_vcap_services,
    get_redis_settings_from_vcap_services,
)


class TestCloudFoundrySettings:
    def test_get_database_settings_from_vcap_services_maps_primary_and_replica(self):
        settings_by_alias = get_database_settings_from_vcap_services(
            {
                "aws-rds": [
                    {
                        "credentials": {
                            "uri": "postgres://db-user:db-pass@db.example.com:5432/prowler",
                            "replica_uri": "postgres://replica-user:replica-pass@replica.example.com:5432/prowler",
                        }
                    }
                ]
            }
        )

        assert settings_by_alias is not None
        assert settings_by_alias["prowler_user"]["HOST"] == "db.example.com"
        assert settings_by_alias["admin"]["USER"] == "db-user"
        assert settings_by_alias["replica"]["HOST"] == "replica.example.com"
        assert settings_by_alias["admin_replica"]["PASSWORD"] == "replica-pass"
        assert settings_by_alias["admin"]["OPTIONS"] == {"sslmode": "require"}

    def test_build_django_databases_from_vcap_services_sets_default_and_engine(self):
        databases = build_django_databases_from_vcap_services(
            {
                "aws-rds": [
                    {
                        "credentials": {
                            "uri": "postgres://db-user:db-pass@db.example.com:5432/prowler"
                        }
                    }
                ]
            }
        )

        assert databases is not None
        assert databases["default"]["ENGINE"] == "psqlextra.backend"
        assert databases["default"]["HOST"] == "db.example.com"
        assert databases["admin"]["USER"] == "db-user"

    def test_get_redis_settings_from_vcap_services_uses_bound_uri(self):
        redis_settings = get_redis_settings_from_vcap_services(
            {
                "aws-elasticache-redis": [
                    {
                        "credentials": {
                            "uri": "rediss://default:secret@cache.example.com:6379/1"
                        }
                    }
                ]
            }
        )

        assert redis_settings == {
            "scheme": "rediss",
            "username": "default",
            "password": "secret",
            "host": "cache.example.com",
            "port": "6379",
            "db": "1",
        }

    def test_get_hosts_and_cors_origins_from_vcap_application(self):
        vcap_application = {
            "application_uris": ["prowler-api.example.app.cloud.gov"]
        }

        assert get_allowed_hosts_from_vcap_application(
            ["localhost"], vcap_application
        ) == ["localhost", "prowler-api.example.app.cloud.gov"]
        assert get_cors_origins_from_vcap_application(
            ["http://localhost"], vcap_application
        ) == ["http://localhost", "https://prowler-api.example.app.cloud.gov"]