from unittest import mock

from prowler.providers.aws.services.codebuild.codebuild_service import (
    Project,
    Webhook,
    WebhookFilter,
    WebhookFilterGroup,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_codebuild_project_webhook_filters_use_anchored_patterns:
    def test_no_projects(self):
        codebuild_client = mock.MagicMock
        codebuild_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 0

    def test_project_without_webhook(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=None,
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "no webhook configured or all webhook filter patterns are properly anchored"
                in result[0].status_extended
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].region == AWS_REGION

    def test_project_webhook_empty_filter_groups(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(filter_groups=[]),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "no webhook configured or all webhook filter patterns are properly anchored"
                in result[0].status_extended
            )

    def test_project_webhook_with_anchored_patterns(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="^123456789$|^987654321$",
                                ),
                                WebhookFilter(
                                    type="HEAD_REF",
                                    pattern="^refs/heads/main$",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "no webhook configured or all webhook filter patterns are properly anchored"
                in result[0].status_extended
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].region == AWS_REGION

    def test_project_webhook_with_unanchored_patterns(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="123456|234567",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unanchored patterns" in result[0].status_extended
            assert "ACTOR_ACCOUNT_ID" in result[0].status_extended
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].region == AWS_REGION

    def test_project_webhook_with_mixed_anchored_unanchored(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="^123456$|234567",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unanchored patterns" in result[0].status_extended

    def test_project_multiple_filter_groups_one_bad(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="^123456789$",
                                ),
                            ]
                        ),
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="BASE_REF",
                                    pattern="refs/heads/main",
                                ),
                            ]
                        ),
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "BASE_REF" in result[0].status_extended
            assert "unanchored patterns" in result[0].status_extended

    def test_project_non_high_risk_filter_unanchored(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="EVENT",
                                    pattern="PUSH|PULL_REQUEST_MERGED",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "no webhook configured or all webhook filter patterns are properly anchored"
                in result[0].status_extended
            )

    def test_project_multiple_unanchored_filters_truncated(self):
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="123456",
                                ),
                                WebhookFilter(
                                    type="HEAD_REF",
                                    pattern="refs/heads/main",
                                ),
                                WebhookFilter(
                                    type="BASE_REF",
                                    pattern="refs/heads/develop",
                                ),
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="987654",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "and 1 more" in result[0].status_extended

    def test_project_webhook_with_empty_pattern(self):
        """Empty patterns should PASS as they don't pose a bypass risk."""
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_project_webhook_with_start_anchor_only(self):
        """Pattern with only start anchor (^) should FAIL."""
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="^123456789",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unanchored patterns" in result[0].status_extended

    def test_project_webhook_with_end_anchor_only(self):
        """Pattern with only end anchor ($) should FAIL."""
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="123456789$",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unanchored patterns" in result[0].status_extended

    def test_project_webhook_codebreach_research_vulnerable_pattern(self):
        """Test with the exact vulnerable pattern from Wiz CodeBreach research - should FAIL."""
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="16024985|755743|48153483|191175973|47447266|213081198",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unanchored patterns" in result[0].status_extended
            assert "ACTOR_ACCOUNT_ID" in result[0].status_extended

    def test_project_webhook_codebreach_research_fixed_pattern(self):
        """Test with the properly anchored version of the research pattern - should PASS."""
        codebuild_client = mock.MagicMock
        project_name = "test-project"
        project_arn = f"arn:aws:codebuild:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:project/{project_name}"
        codebuild_client.projects = {
            project_arn: Project(
                name=project_name,
                arn=project_arn,
                region=AWS_REGION,
                webhook=Webhook(
                    filter_groups=[
                        WebhookFilterGroup(
                            filters=[
                                WebhookFilter(
                                    type="ACTOR_ACCOUNT_ID",
                                    pattern="^16024985$|^755743$|^48153483$|^191175973$|^47447266$|^213081198$",
                                ),
                            ]
                        )
                    ]
                ),
                tags=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_webhook_filters_use_anchored_patterns.codebuild_project_webhook_filters_use_anchored_patterns import (
                codebuild_project_webhook_filters_use_anchored_patterns,
            )

            check = codebuild_project_webhook_filters_use_anchored_patterns()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "no webhook configured or all webhook filter patterns are properly anchored"
                in result[0].status_extended
            )
