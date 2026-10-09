from datetime import date
from unittest import mock

from prowler.providers.m365.services.entra.entra_service import Group
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_dynamic_group_member_of_rule_not_used."
    "entra_dynamic_group_member_of_rule_not_used"
)


class Test_entra_dynamic_group_member_of_rule_not_used:
    """Tests for the entra_dynamic_group_member_of_rule_not_used check."""

    def test_no_dynamic_groups(self):
        """No dynamic groups exist — check returns no findings."""
        entra_client = mock.MagicMock()
        entra_client.groups = []
        entra_client.groups_error = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 0

    def test_only_assigned_groups(self):
        """Assigned (non-dynamic) groups produce no findings."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-assigned",
                name="Static Group",
                groupTypes=["Unified"],
                membershipRule=None,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 0

    def test_groups_error_returns_manual(self):
        """When groups could not be read, emit a single MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = (
            "Unable to retrieve groups from Microsoft Graph (ODataError)"
        )
        entra_client.groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "groups"
            assert result[0].resource_name == "Dynamic groups"
            assert "Cannot evaluate" in result[0].status_extended
            assert result[0].status_extended.endswith(".")

    def test_dynamic_group_null_rule_returns_manual(self):
        """A dynamic group with a null membership rule produces MANUAL."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-null-rule",
                name="Null Rule Group",
                groupTypes=["DynamicMembership"],
                membershipRule=None,
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be read" in result[0].status_extended

    def test_dynamic_group_empty_rule_returns_manual(self):
        """A dynamic group with an empty membership rule produces MANUAL."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-empty-rule",
                name="Empty Rule Group",
                groupTypes=["DynamicMembership"],
                membershipRule="",
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"

    def test_pass_no_memberof_rule(self):
        """A dynamic group with attribute-based rule passes."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-pass",
                name="Guests",
                groupTypes=["DynamicMembership"],
                membershipRule='(user.userType -eq "Guest")',
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "g-pass"
            assert result[0].resource_name == "Guests"
            assert "does not use the memberOf" in result[0].status_extended
            assert result[0].status_extended.endswith(".")

    def test_fail_user_memberof_before_retirement(self):
        """A dynamic group using user.memberof fails with pre-retirement wording."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-fail-user",
                name="All Finance (memberOf)",
                groupTypes=["DynamicMembership"],
                membershipRule="user.memberof -any (group.objectId -in ['0282e19d-bf41-435d-92a4-99bab93af305','11111111-2222-3333-4444-555555555555'])",
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "g-fail-user"
            assert "processing: On" in result[0].status_extended
            assert "is being retired on November 3, 2026" in result[0].status_extended
            assert "0282e19d-bf41-435d-92a4-99bab93af305" in result[0].status_extended
            assert "11111111-2222-3333-4444-555555555555" in result[0].status_extended
            assert result[0].status_extended.endswith(".")

    def test_fail_device_memberof_after_retirement(self):
        """A dynamic group using device.memberof fails with post-retirement wording."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-fail-device",
                name="Corp Devices",
                groupTypes=["DynamicMembership"],
                membershipRule="device.memberOf -any (group.objectId -in ['aabbccdd-1122-3344-5566-778899001122'])",
                membership_rule_processing_state="Paused",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 11, 3)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "processing: Paused" in result[0].status_extended
            assert "was retired on November 3, 2026" in result[0].status_extended
            assert "aabbccdd-1122-3344-5566-778899001122" in result[0].status_extended

    def test_no_false_positive_memberof_in_quoted_string(self):
        """memberOf inside a quoted literal must not trigger a FAIL."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-quoted",
                name="Dept Group",
                groupTypes=["DynamicMembership"],
                membershipRule='user.department -eq "user.memberOf"',
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail_memberof_after_backtick_escaped_quote(self):
        """A backtick-escaped quote in an earlier literal must not hide memberOf."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-escaped",
                name="Escaped Quote Group",
                groupTypes=["DynamicMembership"],
                membershipRule=(
                    'user.department -eq "R`"D" -or user.memberof -any '
                    "(group.objectId -in ['11111111-1111-1111-1111-111111111111']) "
                    '-or user.city -eq "Madrid"'
                ),
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_case_insensitive_detection(self):
        """Detection is case-insensitive (User.MemberOf should FAIL)."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-case",
                name="Case Group",
                groupTypes=["DynamicMembership"],
                membershipRule="User.MemberOf -any (group.objectId -in ['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'])",
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiline_rule_normalised(self):
        """Rules with CR/LF are normalised before matching."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-multiline",
                name="Multiline Group",
                groupTypes=["DynamicMembership"],
                membershipRule="user.memberof\r\n-any (group.objectId -in ['12345678-1234-1234-1234-123456789abc'])",
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "12345678-1234-1234-1234-123456789abc" in result[0].status_extended

    def test_mixed_groups_pass_and_fail(self):
        """Multiple groups: one PASS, one FAIL, one assigned (skipped)."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-assigned",
                name="Static Group",
                groupTypes=["Unified"],
                membershipRule=None,
            ),
            Group(
                id="g-good",
                name="Good Dynamic",
                groupTypes=["DynamicMembership"],
                membershipRule='(user.department -eq "Engineering")',
                membership_rule_processing_state="On",
            ),
            Group(
                id="g-bad",
                name="Bad Dynamic",
                groupTypes=["DynamicMembership"],
                membershipRule="user.memberof -any (group.objectId -in ['abcdef01-2345-6789-abcd-ef0123456789'])",
                membership_rule_processing_state="On",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            # Assigned group is skipped, so 2 findings
            assert len(result) == 2
            statuses = {r.resource_id: r.status for r in result}
            assert statuses["g-good"] == "PASS"
            assert statuses["g-bad"] == "FAIL"

    def test_fail_unknown_processing_state(self):
        """When processing state is None, it shows as 'Unknown'."""
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-unknown-state",
                name="Unknown State Group",
                groupTypes=["DynamicMembership"],
                membershipRule="user.memberof -any (group.objectId -in ['aabbccdd-0000-1111-2222-333344445555'])",
                membership_rule_processing_state=None,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "processing: Unknown" in result[0].status_extended

    def test_duplicate_guids_deduplicated(self):
        """Duplicate GUIDs in the rule are deduplicated in status_extended."""
        guid = "aabbccdd-1122-3344-5566-778899001122"
        entra_client = mock.MagicMock()
        entra_client.groups_error = None
        entra_client.groups = [
            Group(
                id="g-dup-guid",
                name="Dup GUID Group",
                groupTypes=["DynamicMembership"],
                membershipRule=f"user.memberof -any (group.objectId -in ['{guid}','{guid}'])",
                membership_rule_processing_state="On",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.date",
                wraps=date,
            ) as mock_date,
        ):
            mock_date.today.return_value = date(2026, 10, 1)

            from prowler.providers.m365.services.entra.entra_dynamic_group_member_of_rule_not_used.entra_dynamic_group_member_of_rule_not_used import (
                entra_dynamic_group_member_of_rule_not_used,
            )

            check = entra_dynamic_group_member_of_rule_not_used()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            # GUID should appear only once in the source group list
            assert result[0].status_extended.count(guid) == 1
