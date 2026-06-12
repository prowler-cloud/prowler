from types import SimpleNamespace

from prowler.lib.outputs.compliance.okta_idaas_stig.okta_idaas_stig import (
    get_okta_idaas_stig_table,
)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _make_compliance(provider, sections):
    """Build a per-check Okta-IDaaS-STIG compliance covering the given sections."""
    return SimpleNamespace(
        Framework="Okta-IDaaS-STIG",
        Provider=provider,
        Requirements=[
            SimpleNamespace(Attributes=[SimpleNamespace(Section=section)])
            for section in sections
        ],
    )


class TestOktaIDaaSSTIGTable:
    def test_multi_section_fail_not_undercounted(self, capsys):
        """A single FAIL check mapped to several sections must show FAIL(1) in
        every section, not just the first one seen (PROWLER-1963)."""
        bulk_metadata = {
            # check_a belongs to two sections at once.
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("okta", ["IAM", "Logging"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("okta", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_okta_idaas_stig_table(
            findings,
            bulk_metadata,
            "okta_idaas_stig_1r2",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        # Both IAM and Logging must report FAIL(1); before the fix Logging
        # was undercounted and rendered as plain PASS.
        assert captured.out.count("FAIL(1)") == 2

    def test_provider_column_uses_framework_provider(self, capsys):
        """The Provider column must come from the matched framework, never
        from a leaked loop variable (PROWLER-1963)."""
        bulk_metadata = {
            "check_a": SimpleNamespace(Compliance=[_make_compliance("okta", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_a", "PASS"),
        ]

        get_okta_idaas_stig_table(
            findings,
            bulk_metadata,
            "okta_idaas_stig_1r2",
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        assert "okta" in captured.out
