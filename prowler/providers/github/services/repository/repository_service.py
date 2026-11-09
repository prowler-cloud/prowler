from datetime import datetime
from fnmatch import fnmatch
from typing import Optional

import github
import requests
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.lib.service.service import GithubService
from prowler.providers.github.models import GithubAppIdentityInfo

GITHUB_GRAPHQL_TIMEOUT = (10, 60)


class Repository(GithubService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.repositories = self._list_repositories()

    def _file_exists(self, repo, filename):
        """Check if a file exists in the repository. Returns True if exists, False if not, None if error."""
        try:
            return repo.get_contents(filename) is not None
        except Exception as error:
            if "404" in str(error):
                return False
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                return None

    def _validate_repository_format(self, repo_name: str) -> bool:
        """
        Validate repository name format.

        Args:
            repo_name: Repository name to validate

        Returns:
            bool: True if format is valid, False otherwise
        """
        if not repo_name or "/" not in repo_name:
            return False

        parts = repo_name.split("/")
        if len(parts) != 2:
            return False

        owner, repo = parts
        # Ensure both owner and repo names are non-empty
        if not owner.strip() or not repo.strip():
            return False

        return True

    def _get_accessible_repos_graphql(self) -> list[str]:
        """
        Use the GitHub GraphQL API to list all repositories that the authentication token has access to.
        This works with high-granularity (fine-grained) PATs.
        """
        graphql_url = "https://api.github.com/graphql"
        token = self.provider.session.token
        headers = {
            "Authorization": f"bearer {token}",
            "Content-Type": "application/json",
        }
        query = """
        query ($cursor: String) {
          viewer {
            repositories(
              first: 100
              after: $cursor
              affiliations: [OWNER, ORGANIZATION_MEMBER]
            ) {
              nodes {
                nameWithOwner
              }
              pageInfo {
                hasNextPage
                endCursor
              }
            }
          }
        }
        """

        repositories = []
        cursor = None
        seen_cursors = set()

        try:
            while True:
                response = requests.post(
                    graphql_url,
                    json={"query": query, "variables": {"cursor": cursor}},
                    headers=headers,
                    timeout=GITHUB_GRAPHQL_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()

                errors = data.get("errors") if isinstance(data, dict) else None
                repository_connection = (
                    ((data.get("data") or {}).get("viewer") or {}).get("repositories")
                    if isinstance(data, dict)
                    else None
                )
                if not isinstance(repository_connection, dict):
                    logger.error(
                        f"Error in GraphQL query: {errors or 'invalid response'}"
                    )
                    return repositories
                if errors:
                    # GitHub returns partial responses: repositories the token
                    # cannot access (e.g. behind organization SAML enforcement)
                    # come back as null nodes together with an "errors" entry,
                    # while the rest of the page is valid.
                    logger.warning(
                        f"GitHub GraphQL returned errors while discovering repositories, "
                        f"some repositories may be skipped: {errors}"
                    )

                repo_nodes = repository_connection.get("nodes")
                page_info = repository_connection.get("pageInfo")
                if (
                    not isinstance(repo_nodes, list)
                    or not isinstance(page_info, dict)
                    or not isinstance(page_info.get("hasNextPage"), bool)
                ):
                    logger.error(
                        "GitHub GraphQL returned an invalid repositories page; "
                        "repository discovery may be incomplete."
                    )
                    return repositories

                for repo_node in repo_nodes:
                    if not repo_node:
                        logger.warning(
                            "Skipping a repository the token cannot access during discovery."
                        )
                        continue
                    repositories.append(repo_node["nameWithOwner"])

                if not page_info["hasNextPage"]:
                    return repositories

                cursor = page_info.get("endCursor")
                if not cursor or cursor in seen_cursors:
                    logger.error(
                        "GitHub GraphQL pagination returned an invalid cursor; "
                        "repository discovery may be incomplete."
                    )
                    return repositories
                seen_cursors.add(cursor)

        except (
            requests.exceptions.RequestException,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
        ) as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return repositories

    def _default_branch_matches_rule_pattern(
        self, pattern: str, default_branch: str
    ) -> bool:
        """Check whether a ruleset ref pattern applies to the default branch."""
        branch_ref = f"refs/heads/{default_branch}"

        if pattern in {"~ALL", "~DEFAULT_BRANCH"}:
            return True

        return fnmatch(branch_ref, pattern)

    def _ruleset_targets_default_branch(
        self, ruleset: dict, default_branch: str
    ) -> bool:
        """Check whether a ruleset targets the repository default branch."""
        ref_name_conditions = (ruleset.get("conditions") or {}).get("ref_name")
        if not ref_name_conditions:
            return False

        include_patterns = ref_name_conditions.get("include") or []
        exclude_patterns = ref_name_conditions.get("exclude") or []

        if not include_patterns:
            return False

        if not any(
            self._default_branch_matches_rule_pattern(pattern, default_branch)
            for pattern in include_patterns
        ):
            return False

        return not any(
            self._default_branch_matches_rule_pattern(pattern, default_branch)
            for pattern in exclude_patterns
        )

    def _get_repository_rulesets(self, repo) -> Optional[list[dict]]:
        """Fetch repository and parent branch rulesets with full rule details."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            rulesets = []
            page = 1

            while True:
                _, response = repo._requester.requestJsonAndCheck(  # type: ignore[attr-defined]
                    "GET",
                    f"/repos/{repo.full_name}/rulesets?includes_parents=true&targets=branch&per_page=100&page={page}",
                    headers=headers,
                )

                if not isinstance(response, list):
                    break

                rulesets.extend(response)

                if len(response) < 100:
                    break

                page += 1

            detailed_rulesets = []
            for ruleset in rulesets:
                ruleset_id = ruleset.get("id")
                if ruleset_id is None:
                    continue

                _, ruleset_details = repo._requester.requestJsonAndCheck(  # type: ignore[attr-defined]
                    "GET",
                    f"/repos/{repo.full_name}/rulesets/{ruleset_id}?includes_parents=true",
                    headers=headers,
                )
                if isinstance(ruleset_details, dict):
                    detailed_rulesets.append(ruleset_details)

            return detailed_rulesets
        except github.GithubException as error:
            status_code = getattr(error, "status", None)
            if status_code == 404:
                logger.info(
                    f"{repo.full_name}: rulesets endpoint not available for this repository."
                )
                return None
            if status_code == 403:
                logger.warning(
                    f"{repo.full_name}: insufficient permissions to query repository rulesets."
                )
                return None
            self._handle_github_api_error(
                error, "fetching repository rulesets", repo.full_name
            )
        except Exception as error:
            logger.error(
                f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return None

    @staticmethod
    def _rule_enforces_on_existing_branch(rule: dict) -> bool:
        """Check whether a ruleset rule can enforce anything on an existing branch.

        A creation rule only restricts creating the branch, and a rule configured with
        an empty list of requirements (status checks, deployments, workflows, ...)
        requires nothing.
        """
        rule_type = rule.get("type")
        if rule_type == "creation":
            return False
        list_parameter = {
            "required_status_checks": "required_status_checks",
            "required_deployments": "required_deployment_environments",
            "workflows": "workflows",
            "code_scanning": "code_scanning_tools",
            "file_path_restriction": "restricted_file_paths",
            "file_extension_restriction": "restricted_file_extensions",
        }.get(rule_type)
        if list_parameter is None:
            return True
        return bool((rule.get("parameters") or {}).get(list_parameter))

    def _evaluate_default_branch_rulesets(
        self, repo, default_branch: str
    ) -> dict[str, tuple[Optional[int], str]]:
        """Evaluate default-branch protection coverage provided by rulesets.

        Fetches the repository (and parent) rulesets once and walks every rule that
        targets the default branch, mapping each ruleset rule to its equivalent classic
        branch-protection attribute.

        Returns:
            dict mapping a ``Branch`` attribute name to a ``(value, source)`` tuple where
            ``source`` is ``"ruleset"`` (enforced by an active ruleset), ``"ruleset_not_active"``
            (configured by a ruleset that is not active), ``"ruleset_unknown"`` (an active
            ruleset whose coverage GitHub did not disclose) or absent when no ruleset
            addresses the attribute. ``value`` is only meaningful for ``approval_count`` (the enforced
            review count); for boolean attributes it is ``None`` and the caller derives the
            value from ``source`` and the attribute polarity.
        """
        result: dict[str, tuple[Optional[int], str]] = {}
        rulesets = self._get_repository_rulesets(repo)
        if not rulesets:
            return result

        active: set[str] = set()
        inactive: set[str] = set()
        active_approval_count: Optional[int] = None
        inactive_approval_count: Optional[int] = None
        any_active_ruleset = False
        any_active_ruleset_unknown = False
        any_inactive_ruleset = False
        # A ruleset only counts as coverage when GitHub returned evidence that it enforces
        # something on the existing default branch; missing details mean unknown, never
        # pass or fail. Rules that enforce nothing there (branch creation restrictions and
        # rules with an empty list of requirements) are dropped, and a ruleset left
        # without rules is ignored. An active ruleset whose rules GitHub omits leaves every control it
        # could enforce unknown. A ruleset applies to administrators (the rulesets
        # equivalent of "enforce admins") unless a bypass actor could be an administrator;
        # integrations and deploy keys cannot. Only an explicit ``bypass_actors`` list
        # together with returned rule details confirms admin coverage, because GitHub
        # omits fields the token cannot read.
        admins_enforced_active = False
        admins_coverage_unknown_active = False
        admins_configured_inactive = False

        for ruleset in rulesets:
            if ruleset.get("target") != "branch":
                continue

            if not self._ruleset_targets_default_branch(ruleset, default_branch):
                continue

            enforcement = ruleset.get("enforcement")
            is_active = enforcement in {"active", "enabled"}
            is_inactive = enforcement in {"disabled", "evaluate"}
            if not (is_active or is_inactive):
                continue

            rules = ruleset.get("rules")
            if isinstance(rules, list):
                rules = [
                    rule
                    for rule in rules
                    if self._rule_enforces_on_existing_branch(rule)
                ]
                if not rules:
                    continue

            bypass_actors = ruleset.get("bypass_actors")
            bypass_known = isinstance(bypass_actors, list)
            admins_can_bypass = bypass_known and any(
                actor.get("actor_type") not in {"Integration", "DeployKey"}
                for actor in bypass_actors
            )
            if is_active:
                if rules is None:
                    any_active_ruleset_unknown = True
                else:
                    any_active_ruleset = True
                if not admins_can_bypass:
                    if bypass_known and rules is not None:
                        admins_enforced_active = True
                    else:
                        admins_coverage_unknown_active = True
            elif rules is not None:
                any_inactive_ruleset = True
                if bypass_known and not admins_can_bypass:
                    admins_configured_inactive = True

            bucket = active if is_active else inactive

            for rule in rules or []:
                rule_type = rule.get("type")
                params = rule.get("parameters") or {}

                if rule_type == "required_linear_history":
                    bucket.add("required_linear_history")
                elif rule_type == "required_signatures":
                    bucket.add("require_signed_commits")
                elif rule_type == "required_status_checks":
                    bucket.add("status_checks")
                elif rule_type == "non_fast_forward":
                    # Presence of the rule disallows force pushes.
                    bucket.add("allow_force_pushes")
                elif rule_type == "deletion":
                    # Presence of the rule disallows branch deletion.
                    bucket.add("branch_deletion")
                elif rule_type == "pull_request":
                    bucket.add("require_pull_request")
                    if params.get("require_code_owner_review") is True:
                        bucket.add("require_code_owner_reviews")
                    if params.get("required_review_thread_resolution") is True:
                        bucket.add("conversation_resolution")
                    if params.get("dismiss_stale_reviews_on_push") is True:
                        bucket.add("dismiss_stale_reviews")
                    count = params.get("required_approving_review_count")
                    if isinstance(count, int):
                        if is_active:
                            active_approval_count = max(
                                active_approval_count or 0, count
                            )
                        else:
                            inactive_approval_count = max(
                                inactive_approval_count or 0, count
                            )

        for concept in (
            "required_linear_history",
            "require_signed_commits",
            "status_checks",
            "allow_force_pushes",
            "branch_deletion",
            "require_pull_request",
            "require_code_owner_reviews",
            "conversation_resolution",
            "dismiss_stale_reviews",
        ):
            if concept in active:
                result[concept] = (None, "ruleset")
            elif any_active_ruleset_unknown:
                result[concept] = (None, "ruleset_unknown")
            elif concept in inactive:
                result[concept] = (None, "ruleset_not_active")

        if any_active_ruleset_unknown:
            # The value is only the count confirmed by other active rulesets.
            result["approval_count"] = (active_approval_count, "ruleset_unknown")
        elif active_approval_count is not None:
            result["approval_count"] = (active_approval_count, "ruleset")
        elif inactive_approval_count is not None:
            result["approval_count"] = (inactive_approval_count, "ruleset_not_active")

        if any_active_ruleset:
            result["protected"] = (None, "ruleset")
        elif any_active_ruleset_unknown:
            result["protected"] = (None, "ruleset_unknown")
        elif any_inactive_ruleset:
            result["protected"] = (None, "ruleset_not_active")

        if admins_enforced_active:
            result["enforce_admins"] = (None, "ruleset")
        elif admins_coverage_unknown_active:
            result["enforce_admins"] = (None, "ruleset_unknown")
        elif admins_configured_inactive:
            result["enforce_admins"] = (None, "ruleset_not_active")

        return result

    @staticmethod
    def _merge_ruleset_bool(
        classic_value: Optional[bool], ruleset_source: Optional[str], good: bool = True
    ) -> tuple[Optional[bool], Optional[str]]:
        """Merge a boolean branch-protection attribute with its ruleset evaluation.

        Args:
            classic_value: The value resolved from classic branch protection.
            ruleset_source: ``"ruleset"``, ``"ruleset_not_active"``, ``"ruleset_unknown"``
                or ``None``.
            good: The compliant value for the attribute (``True`` for positive attributes,
                ``False`` for inverted ones such as ``allow_force_pushes``).

        Returns:
            A ``(value, source)`` tuple. Classic protection wins when it already satisfies
            the control; otherwise an active ruleset enforces the compliant value, and an
            inactive ruleset surfaces the non-compliant value with a ``"ruleset_not_active"``
            source so checks can explain the gap. An active ruleset whose coverage cannot
            be confirmed (``"ruleset_unknown"``) leaves a non-passing value unknown. An
            unknown classic value (``None``) is only resolved by an active ruleset;
            otherwise it stays unknown.
        """
        if classic_value is None and ruleset_source != "ruleset":
            return None, None
        classic_pass = classic_value == good
        if ruleset_source == "ruleset":
            return good, "ruleset"
        if ruleset_source == "ruleset_not_active" and not classic_pass:
            return (not good), "ruleset_not_active"
        if ruleset_source == "ruleset_unknown" and not classic_pass:
            return None, None
        return classic_value, ("classic" if classic_pass else None)

    def _list_repositories(self):
        """
        List repositories based on provider scoping configuration.
        If the provider is a GitHub App, it will list repositories in the organizations that the GitHub App is installed in.
        If the provider is a user, it will list repositories where the user is a member or owner.
        If input repositories are provided, it will list repositories that match the input repositories.
        If input organizations are provided, it will list repositories in the organizations that match the input organizations.
        """
        logger.info("Repository - Listing Repositories...")
        repos = {}
        try:
            for client in self.clients:
                if (
                    self.provider.repositories
                    or self.provider.organizations
                    or (
                        isinstance(self.provider.identity, GithubAppIdentityInfo)
                        and self.provider.identity.installations
                    )
                ):
                    if self.provider.repositories:
                        qualified_repos = []
                        for repo_name in self.provider.repositories:
                            if self._validate_repository_format(repo_name):
                                qualified_repos.append(repo_name)
                            elif self.provider.organizations:
                                for org_name in self.provider.organizations:
                                    qualified_repos.append(f"{org_name}/{repo_name}")
                            else:
                                logger.warning(
                                    f"Repository name '{repo_name}' should be in 'owner/repo-name' format. Skipping."
                                )

                        logger.info(
                            f"Filtering for specific repositories: {qualified_repos}"
                        )
                        for repo_name in qualified_repos:
                            try:
                                repo = client.get_repo(repo_name)
                                self._process_repository(repo, repos)
                            except github.RateLimitExceededException:
                                # Rate limits are transient and must not leave the
                                # scan running with an incomplete repository set
                                raise
                            except Exception as error:
                                self._handle_github_api_error(
                                    error, "accessing repository", repo_name
                                )

                    elif self.provider.organizations:
                        logger.info(
                            f"Filtering for repositories in organizations: {self.provider.organizations}"
                        )
                        for org_name in self.provider.organizations:
                            try:
                                repos_list, _ = self._get_repositories_from_owner(
                                    client, org_name
                                )
                                for repo in repos_list:
                                    self._process_repository(repo, repos)
                            except github.RateLimitExceededException:
                                # Rate limits are transient and must not leave the
                                # scan running with an incomplete repository set
                                raise
                            except Exception as error:
                                self._handle_github_api_error(
                                    error, "processing organization", org_name
                                )
                    elif (
                        isinstance(self.provider.identity, GithubAppIdentityInfo)
                        and self.provider.identity.installations
                        and not self.provider.repositories
                    ):
                        logger.info(
                            f"Filtering for repositories in the organizations or accounts that the GitHub App is installed in: {', '.join(self.provider.identity.installations)}"
                        )
                        for org_name in self.provider.identity.installations:
                            try:
                                repos_list, _ = self._get_repositories_from_owner(
                                    client, org_name
                                )
                                for repo in repos_list:
                                    self._process_repository(repo, repos)
                            except github.RateLimitExceededException:
                                # Rate limits are transient and must not leave the
                                # scan running with an incomplete repository set
                                raise
                            except Exception as error:
                                self._handle_github_api_error(
                                    error, "processing organization", org_name
                                )
                else:
                    logger.info(
                        "No repository or organization specified, discovering accessible repositories via GraphQL API..."
                    )
                    accessible_repo_names = self._get_accessible_repos_graphql()

                    if not accessible_repo_names:
                        logger.warning(
                            "Could not find any accessible repositories with the provided token."
                        )

                    for repo_name in accessible_repo_names:
                        try:
                            repo = client.get_repo(repo_name)
                            logger.info(
                                f"Processing repository found via GraphQL: {repo.full_name}"
                            )
                            self._process_repository(repo, repos)
                        except github.RateLimitExceededException:
                            # Rate limits are transient and must not leave the
                            # scan running with an incomplete repository set
                            raise
                        except Exception as error:
                            if hasattr(self, "_handle_github_api_error"):
                                self._handle_github_api_error(
                                    error,
                                    "accessing repository discovered via GraphQL",
                                    repo_name,
                                )
                            else:
                                logger.error(
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )

        except github.RateLimitExceededException as error:
            logger.error(f"GitHub API rate limit exceeded: {error}")
            raise
        except github.GithubException as error:
            logger.error(f"GitHub API error while listing repositories: {error}")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return repos

    def _process_repository(self, repo, repos):
        """Process a single repository and extract all its information."""
        try:
            default_branch = repo.default_branch
            securitymd_exists = self._file_exists(repo, "SECURITY.md")
            # CODEOWNERS file can be in .github/, root, or docs/
            # https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
            codeowners_paths = [
                ".github/CODEOWNERS",
                "CODEOWNERS",
                "docs/CODEOWNERS",
            ]
            codeowners_files = [
                self._file_exists(repo, path) for path in codeowners_paths
            ]
            if True in codeowners_files:
                codeowners_exists = True
            elif all(file is None for file in codeowners_files):
                codeowners_exists = None
            else:
                codeowners_exists = False
            # GitHub API only returns delete_branch_on_merge with Administration: Read and Write
            # With Read-only permission, it returns None - set to None for MANUAL status
            delete_branch_on_merge = repo.delete_branch_on_merge

            require_pr = False
            approval_cnt = 0
            branch_protection = False
            required_linear_history = False
            allow_force_pushes = True
            branch_deletion = True
            require_code_owner_reviews = False
            require_signed_commits = False
            status_checks = False
            enforce_admins = False
            conversation_resolution = False
            dismiss_stale_reviews = False
            dismiss_stale_reviews_source = None
            protected_source = None
            require_pull_request_source = None
            approval_count_source = None
            required_linear_history_source = None
            allow_force_pushes_source = None
            branch_deletion_source = None
            require_code_owner_reviews_source = None
            require_signed_commits_source = None
            status_checks_source = None
            enforce_admins_source = None
            conversation_resolution_source = None
            branch_is_protected = False
            try:
                branch = repo.get_branch(default_branch)
                branch_is_protected = bool(branch.protected)
                if branch_is_protected:
                    protection = branch.get_protection()
                    if protection:
                        require_pr = (
                            protection.required_pull_request_reviews is not None
                        )
                        approval_cnt = (
                            protection.required_pull_request_reviews.required_approving_review_count
                            if require_pr
                            else 0
                        )
                        required_linear_history = protection.required_linear_history
                        allow_force_pushes = protection.allow_force_pushes
                        branch_deletion = protection.allow_deletions
                        status_checks = protection.required_status_checks is not None
                        enforce_admins = protection.enforce_admins
                        conversation_resolution = (
                            protection.required_conversation_resolution
                        )
                        branch_protection = True
                        require_code_owner_reviews = (
                            protection.required_pull_request_reviews.require_code_owner_reviews
                            if require_pr
                            else False
                        )
                        dismiss_stale_reviews = (
                            protection.required_pull_request_reviews.dismiss_stale_reviews
                            if require_pr
                            else False
                        )
                        if dismiss_stale_reviews:
                            dismiss_stale_reviews_source = "classic"
            except Exception as error:
                error_message = str(error)
                # A 404 means there is no classic protection only when the branch itself is
                # missing (empty repository) or GitHub explicitly answers "Branch not protected".
                # GitHub also answers 404 to the protection endpoints when the token lacks
                # Administration: read on a branch it reports as protected; that state is unknown.
                if "404" in error_message and (
                    not branch_is_protected or "Branch not protected" in error_message
                ):
                    logger.warning(
                        f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                # Any other error (including unreadable protection), we cannot know the state
                else:
                    require_pr = None
                    approval_cnt = None
                    branch_protection = None
                    required_linear_history = None
                    allow_force_pushes = None
                    branch_deletion = None
                    require_code_owner_reviews = None
                    require_signed_commits = None
                    status_checks = None
                    enforce_admins = None
                    conversation_resolution = None
                    dismiss_stale_reviews = None
                    dismiss_stale_reviews_source = None
                    if "404" in error_message:
                        logger.warning(
                            f"{repo.full_name}: branch '{default_branch}' is reported as protected but its protection settings cannot be read (404); the token likely lacks Administration: read, so the classic protection state is unknown"
                        )
                    else:
                        logger.error(
                            f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

            # Required signatures live behind a separate endpoint, so a failure there only
            # makes the signature state unknown and must not discard the classic settings
            # that were already read.
            if branch_protection:
                try:
                    require_signed_commits = branch.get_required_signatures()
                except Exception as error:
                    require_signed_commits = None
                    logger.warning(
                        f"{repo.full_name}: required signatures for branch '{default_branch}' cannot be read, so the signed commits state is unknown: {error}"
                    )

            # Branch protection enforced through rulesets is equivalent to classic branch
            # protection, so merge any ruleset coverage before reporting findings to avoid
            # false positives for repositories that have migrated to rulesets. Rulesets are
            # evaluated even when classic protection is unknown: an active ruleset is a fact
            # about the branch regardless of what the token can read about classic protection.
            ruleset_eval = self._evaluate_default_branch_rulesets(repo, default_branch)

            branch_protection, protected_source = self._merge_ruleset_bool(
                branch_protection, ruleset_eval.get("protected", (None, None))[1]
            )
            require_pr, require_pull_request_source = self._merge_ruleset_bool(
                require_pr,
                ruleset_eval.get("require_pull_request", (None, None))[1],
            )
            (
                required_linear_history,
                required_linear_history_source,
            ) = self._merge_ruleset_bool(
                required_linear_history,
                ruleset_eval.get("required_linear_history", (None, None))[1],
            )
            (
                require_signed_commits,
                require_signed_commits_source,
            ) = self._merge_ruleset_bool(
                require_signed_commits,
                ruleset_eval.get("require_signed_commits", (None, None))[1],
            )
            status_checks, status_checks_source = self._merge_ruleset_bool(
                status_checks, ruleset_eval.get("status_checks", (None, None))[1]
            )
            (
                require_code_owner_reviews,
                require_code_owner_reviews_source,
            ) = self._merge_ruleset_bool(
                require_code_owner_reviews,
                ruleset_eval.get("require_code_owner_reviews", (None, None))[1],
            )
            (
                conversation_resolution,
                conversation_resolution_source,
            ) = self._merge_ruleset_bool(
                conversation_resolution,
                ruleset_eval.get("conversation_resolution", (None, None))[1],
            )
            enforce_admins, enforce_admins_source = self._merge_ruleset_bool(
                enforce_admins,
                ruleset_eval.get("enforce_admins", (None, None))[1],
            )
            allow_force_pushes, allow_force_pushes_source = self._merge_ruleset_bool(
                allow_force_pushes,
                ruleset_eval.get("allow_force_pushes", (None, None))[1],
                good=False,
            )
            branch_deletion, branch_deletion_source = self._merge_ruleset_bool(
                branch_deletion,
                ruleset_eval.get("branch_deletion", (None, None))[1],
                good=False,
            )

            # Dismiss stale reviews keeps its dedicated handling so the classic source
            # set above (when enabled) is preserved.
            _, dismiss_source = ruleset_eval.get("dismiss_stale_reviews", (None, None))
            if dismiss_source == "ruleset":
                dismiss_stale_reviews = True
                dismiss_stale_reviews_source = "ruleset"
            elif (
                dismiss_source == "ruleset_not_active"
                and dismiss_stale_reviews is False
            ):
                dismiss_stale_reviews_source = "ruleset_not_active"
            elif dismiss_source == "ruleset_unknown" and dismiss_stale_reviews is False:
                dismiss_stale_reviews = None

            # Approval count takes the strongest requirement between classic and rulesets.
            approval_value, approval_source = ruleset_eval.get(
                "approval_count", (None, None)
            )
            if approval_source == "ruleset" and approval_value is not None:
                if approval_cnt is None:
                    # Classic protection is unknown, so the ruleset count is only a lower
                    # bound: adopt it only when it already satisfies the control.
                    if approval_value >= 2:
                        approval_cnt = approval_value
                        approval_count_source = "ruleset"
                else:
                    if approval_value > approval_cnt:
                        approval_cnt = approval_value
                    approval_count_source = "ruleset"
            elif (
                approval_source == "ruleset_not_active"
                and (approval_value or 0) >= 2
                and approval_cnt is not None
                and approval_cnt < 2
            ):
                approval_count_source = "ruleset_not_active"
            elif approval_source == "ruleset_unknown":
                # An active ruleset's rules are unknown, so only a count that already
                # satisfies the control is known.
                if (approval_value or 0) >= 2 and (
                    approval_cnt is None or approval_value > approval_cnt
                ):
                    approval_cnt = approval_value
                    approval_count_source = "ruleset"
                elif approval_cnt is None or approval_cnt < 2:
                    approval_cnt = None

            secret_scanning_enabled = False
            # GitHub omits security_and_analysis when the token cannot read it
            secret_scanning_push_protection_enabled = None
            dependabot_alerts_enabled = False
            try:
                if (
                    repo.security_and_analysis
                    and repo.security_and_analysis.secret_scanning
                ):
                    secret_scanning_enabled = (
                        repo.security_and_analysis.secret_scanning.status == "enabled"
                    )
                if repo.security_and_analysis:
                    push_protection = (
                        repo.security_and_analysis.secret_scanning_push_protection
                    )
                    secret_scanning_push_protection_enabled = bool(
                        push_protection and push_protection.status == "enabled"
                    )
                try:
                    # Use get_dependabot_alerts to check if Dependabot alerts are enabled
                    repo.get_dependabot_alerts().totalCount
                    # If the call succeeds, Dependabot is enabled (even if no alerts)
                    dependabot_alerts_enabled = True
                except Exception as error:
                    error_str = str(error)
                    if (
                        "403" in error_str
                        and "Dependabot alerts are disabled for this repository."
                        in error_str
                    ):
                        dependabot_alerts_enabled = False
                    else:
                        logger.error(
                            f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        dependabot_alerts_enabled = None
            except Exception as error:
                logger.error(
                    f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                secret_scanning_enabled = None
                secret_scanning_push_protection_enabled = None
                dependabot_alerts_enabled = None
            repos[repo.id] = Repo(
                id=repo.id,
                name=repo.name,
                owner=repo.owner.login,
                full_name=repo.full_name,
                immutable_releases_enabled=self._get_repository_immutable_releases_status(
                    repo
                ),
                default_workflow_permissions=self._get_default_workflow_permissions(
                    repo
                ),
                default_branch=Branch(
                    name=default_branch,
                    protected=branch_protection,
                    protected_source=protected_source,
                    default_branch=True,
                    require_pull_request=require_pr,
                    require_pull_request_source=require_pull_request_source,
                    approval_count=approval_cnt,
                    approval_count_source=approval_count_source,
                    required_linear_history=required_linear_history,
                    required_linear_history_source=required_linear_history_source,
                    allow_force_pushes=allow_force_pushes,
                    allow_force_pushes_source=allow_force_pushes_source,
                    branch_deletion=branch_deletion,
                    branch_deletion_source=branch_deletion_source,
                    status_checks=status_checks,
                    status_checks_source=status_checks_source,
                    enforce_admins=enforce_admins,
                    enforce_admins_source=enforce_admins_source,
                    conversation_resolution=conversation_resolution,
                    conversation_resolution_source=conversation_resolution_source,
                    require_code_owner_reviews=require_code_owner_reviews,
                    require_code_owner_reviews_source=require_code_owner_reviews_source,
                    require_signed_commits=require_signed_commits,
                    require_signed_commits_source=require_signed_commits_source,
                    dismiss_stale_reviews=dismiss_stale_reviews,
                    dismiss_stale_reviews_source=dismiss_stale_reviews_source,
                ),
                private=repo.private,
                archived=repo.archived,
                pushed_at=repo.pushed_at,
                securitymd=securitymd_exists,
                codeowners_exists=codeowners_exists,
                secret_scanning_enabled=secret_scanning_enabled,
                secret_scanning_push_protection_enabled=secret_scanning_push_protection_enabled,
                dependabot_alerts_enabled=dependabot_alerts_enabled,
                delete_branch_on_merge=delete_branch_on_merge,
            )
        except github.RateLimitExceededException:
            raise  # Re-raise rate limit errors so the listing flow can handle them
        except Exception as error:
            logger.error(
                f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_repository_immutable_releases_status(self, repo) -> Optional[bool]:
        """Retrieve the immutable releases status for the provided repository.

        The API returns a response in the format:
        {
            "enabled": true,
            "enforced_by_owner": false
        }

        Args:
            repo: The PyGithub repository instance to query.

        Returns:
            Optional[bool]: True when immutable releases are enabled, False when they are disabled, and None when the status cannot be determined.
        """
        try:
            _, response = repo._requester.requestJsonAndCheck(  # type: ignore[attr-defined]
                "GET",
                f"/repos/{repo.full_name}/immutable-releases",
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if isinstance(response, dict) and "enabled" in response:
                return response.get("enabled")
            return None
        except github.GithubException as error:
            status_code = getattr(error, "status", None)
            if status_code == 404:
                logger.info(
                    f"{repo.full_name}: immutable releases endpoint not available for this repository."
                )
                return None
            if status_code == 403:
                logger.warning(
                    f"{repo.full_name}: insufficient permissions to query immutable releases endpoint."
                )
                return None
            self._handle_github_api_error(
                error, "fetching immutable releases status", repo.full_name
            )
        except Exception as error:
            logger.error(
                f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return None

    def _get_default_workflow_permissions(self, repo) -> Optional[str]:
        """Retrieve the default GITHUB_TOKEN permissions granted to workflows in the repository.

        The API returns a response in the format:
        {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": false
        }

        Args:
            repo: The PyGithub repository instance to query.

        Returns:
            Optional[str]: "read" or "write", and None when the setting cannot be determined.

        Raises:
            github.RateLimitExceededException: When API rate limits are exceeded
        """
        try:
            _, response = repo._requester.requestJsonAndCheck(  # type: ignore[attr-defined]
                "GET",
                f"/repos/{repo.full_name}/actions/permissions/workflow",
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if isinstance(response, dict):
                permissions = response.get("default_workflow_permissions")
                if permissions in ("read", "write"):
                    return permissions
            return None
        except github.RateLimitExceededException as error:
            self._handle_github_api_error(
                error,
                "fetching default workflow permissions",
                repo.full_name,
                reraise_rate_limit=True,
            )
        except github.GithubException as error:
            status_code = getattr(error, "status", None)
            if status_code == 404:
                logger.info(
                    f"{repo.full_name}: Actions workflow permissions endpoint not available for this repository."
                )
                return None
            if status_code == 403:
                logger.warning(
                    f"{repo.full_name}: insufficient permissions to query Actions workflow permissions."
                )
                return None
            self._handle_github_api_error(
                error, "fetching default workflow permissions", repo.full_name
            )
        except Exception as error:
            logger.error(
                f"{repo.full_name}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return None


class Branch(BaseModel):
    """Model for Github Branch"""

    name: str
    protected: Optional[bool]
    protected_source: Optional[str] = None
    default_branch: bool
    require_pull_request: Optional[bool]
    require_pull_request_source: Optional[str] = None
    approval_count: Optional[int]
    approval_count_source: Optional[str] = None
    required_linear_history: Optional[bool]
    required_linear_history_source: Optional[str] = None
    allow_force_pushes: Optional[bool]
    allow_force_pushes_source: Optional[str] = None
    branch_deletion: Optional[bool]
    branch_deletion_source: Optional[str] = None
    status_checks: Optional[bool]
    status_checks_source: Optional[str] = None
    enforce_admins: Optional[bool]
    enforce_admins_source: Optional[str] = None
    require_code_owner_reviews: Optional[bool]
    require_code_owner_reviews_source: Optional[str] = None
    require_signed_commits: Optional[bool]
    require_signed_commits_source: Optional[str] = None
    conversation_resolution: Optional[bool]
    conversation_resolution_source: Optional[str] = None
    dismiss_stale_reviews: Optional[bool]
    dismiss_stale_reviews_source: Optional[str] = None


class Repo(BaseModel):
    """Model for Github Repository"""

    id: int
    name: str
    owner: str
    full_name: str
    immutable_releases_enabled: Optional[bool] = None
    default_workflow_permissions: Optional[str] = None
    default_branch: Branch
    private: bool
    archived: bool
    pushed_at: datetime
    securitymd: Optional[bool]
    codeowners_exists: Optional[bool]
    secret_scanning_enabled: Optional[bool]
    secret_scanning_push_protection_enabled: Optional[bool] = None
    dependabot_alerts_enabled: Optional[bool]
    delete_branch_on_merge: Optional[bool]
