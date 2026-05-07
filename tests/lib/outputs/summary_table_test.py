from types import SimpleNamespace

from prowler.lib.outputs.summary_table import display_summary_table


class TestDisplaySummaryTable:
    def test_azure_summary_shows_display_name_and_subscription_id(self, capsys):
        provider = SimpleNamespace(
            type="azure",
            identity=SimpleNamespace(
                tenant_domain="tenant.example.com",
                tenant_ids=["tenant-id"],
                subscriptions={
                    "subscription-id-1": "Duplicate Subscription",
                    "subscription-id-2": "Duplicate Subscription",
                },
            ),
        )
        output_options = SimpleNamespace(
            output_directory="out",
            output_filename="report",
            output_modes=[],
        )
        findings = [
            SimpleNamespace(
                status="PASS",
                muted=False,
                check_metadata=SimpleNamespace(
                    ServiceName="network",
                    Provider="azure",
                    Severity="low",
                ),
            )
        ]

        display_summary_table(findings, provider, output_options)

        captured = capsys.readouterr()

        assert "Subscriptions scanned:" in captured.out
        assert "Duplicate Subscription (subscription-id-1)" in captured.out
        assert "Duplicate Subscription (subscription-id-2)" in captured.out
