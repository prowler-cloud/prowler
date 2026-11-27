DEFAULT_SP_ENTITY_ID = "urn:prowler.com:sp"


class TestSAMLSPEntityID:
    def _reimport_settings(self):
        """Fresh import: importlib.reload() doesn't clear the module namespace,
        so an attribute set by a prior test would leak into the unset case."""
        import sys

        sys.modules.pop("config.settings.social_login", None)
        import config.settings.social_login as social_login_settings

        return social_login_settings

    def test_unset_defaults_to_prowler_entity_id(self, monkeypatch):
        monkeypatch.delenv("SAML_SP_ENTITY_ID", raising=False)
        mod = self._reimport_settings()

        assert mod.SAML_SP_ENTITY_ID == DEFAULT_SP_ENTITY_ID
        assert (
            mod.SOCIALACCOUNT_PROVIDERS["saml"]["sp"]["entity_id"]
            == DEFAULT_SP_ENTITY_ID
        )

    def test_explicit_value_applied(self, monkeypatch):
        monkeypatch.setenv("SAML_SP_ENTITY_ID", "urn:example.com:sp")
        mod = self._reimport_settings()

        assert mod.SAML_SP_ENTITY_ID == "urn:example.com:sp"
        assert (
            mod.SOCIALACCOUNT_PROVIDERS["saml"]["sp"]["entity_id"]
            == "urn:example.com:sp"
        )
