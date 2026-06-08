from config.django.base import label_postgres_connections


class TestLabelPostgresConnections:
    def test_labels_postgres_and_skips_neo4j(self, monkeypatch):
        monkeypatch.setenv("DJANGO_APP_COMPONENT", "scan")
        databases = {
            "default": {"ENGINE": "psqlextra.backend"},
            "neo4j": {"HOST": "neo4j", "PORT": "7687"},
        }

        label_postgres_connections(databases)

        assert databases["default"]["OPTIONS"]["application_name"] == "scan:default"
        assert "OPTIONS" not in databases["neo4j"]

    def test_labels_plain_postgresql_backend(self, monkeypatch):
        monkeypatch.setenv("DJANGO_APP_COMPONENT", "api")
        databases = {"saas": {"ENGINE": "django.db.backends.postgresql"}}

        label_postgres_connections(databases)

        assert databases["saas"]["OPTIONS"]["application_name"] == "api:saas"

    def test_defaults_component_to_api_when_unset(self, monkeypatch):
        monkeypatch.delenv("DJANGO_APP_COMPONENT", raising=False)
        databases = {"default": {"ENGINE": "psqlextra.backend"}}

        label_postgres_connections(databases)

        assert databases["default"]["OPTIONS"]["application_name"] == "api:default"

    def test_preserves_existing_options(self, monkeypatch):
        monkeypatch.setenv("DJANGO_APP_COMPONENT", "worker")
        databases = {
            "replica": {
                "ENGINE": "psqlextra.backend",
                "OPTIONS": {"sslmode": "require"},
            }
        }

        label_postgres_connections(databases)

        assert databases["replica"]["OPTIONS"] == {
            "sslmode": "require",
            "application_name": "worker:replica",
        }

    def test_truncates_application_name_to_63_bytes(self, monkeypatch):
        monkeypatch.setenv("DJANGO_APP_COMPONENT", "c" * 80)
        databases = {"default": {"ENGINE": "psqlextra.backend"}}

        label_postgres_connections(databases)

        assert len(databases["default"]["OPTIONS"]["application_name"]) == 63
