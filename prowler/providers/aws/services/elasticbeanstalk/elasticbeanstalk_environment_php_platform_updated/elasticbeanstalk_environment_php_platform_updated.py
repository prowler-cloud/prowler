import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)

# "64bit Amazon Linux 2023 v4.13.13 running PHP 8.4"
SOLUTION_STACK_RE = re.compile(
    r"^(?P<family>.+?) v(?P<version>\d+(?:\.\d+)+) running PHP (?P<branch>\d+\.\d+)",
    re.IGNORECASE,
)
# "arn:aws:elasticbeanstalk:us-east-1::platform/PHP 8.4 running on 64bit Amazon Linux 2023/4.13.13"
PLATFORM_ARN_RE = re.compile(
    r"platform/PHP (?P<branch>\d+\.\d+) running on (?P<family>[^/]+)/(?P<version>\d+(?:\.\d+)+)",
    re.IGNORECASE,
)
AMAZON_LINUX_YEAR_RE = re.compile(r"Amazon Linux (\d{4})")
# First Amazon Linux generation that received platform versions with the fixed PHP release
FIXED_PLATFORM_YEAR = 2023


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".")) if value else ()


def _family_has_fixed_releases(family: str) -> bool:
    match = AMAZON_LINUX_YEAR_RE.search(family)
    return bool(match) and int(match.group(1)) >= FIXED_PLATFORM_YEAR


def _php_platform(environment) -> tuple[str, str, str] | None:
    """Return (branch, family, version) for PHP environments, None otherwise."""
    for pattern, value in (
        (SOLUTION_STACK_RE, environment.solution_stack_name),
        (PLATFORM_ARN_RE, environment.platform_arn),
    ):
        match = pattern.search(value or "")
        if match:
            return match["branch"], match["family"], match["version"]
    return None


class elasticbeanstalk_environment_php_platform_updated(Check):
    def execute(self):
        findings = []
        # `or` covers an explicit null in the config file, which .get() would return as None
        min_php_branch = (
            elasticbeanstalk_client.audit_config.get("elasticbeanstalk_php_min_branch")
            or "8.2"
        )
        min_platform_version = (
            elasticbeanstalk_client.audit_config.get(
                "elasticbeanstalk_php_min_platform_version"
            )
            or "4.13.13"
        )

        for environment in elasticbeanstalk_client.environments.values():
            php_platform = _php_platform(environment)
            if not php_platform:
                continue

            php_branch, family, platform_version = php_platform
            stack = environment.solution_stack_name or environment.platform_arn

            report = Check_Report_AWS(metadata=self.metadata(), resource=environment)
            report.status = "FAIL"

            if _version_tuple(php_branch) < _version_tuple(min_php_branch):
                report.status_extended = f"Elastic Beanstalk environment {environment.name} runs PHP {php_branch}, a branch that no longer receives security fixes (minimum supported branch is {min_php_branch})."
            elif not _family_has_fixed_releases(family):
                report.status_extended = f"Elastic Beanstalk environment {environment.name} runs PHP {php_branch} on platform '{stack}', a platform family without fixed PHP releases; migrate it to a PHP {php_branch} Amazon Linux 2023 platform version {min_platform_version} or newer."
            elif _version_tuple(platform_version) < _version_tuple(
                min_platform_version
            ):
                report.status_extended = f"Elastic Beanstalk environment {environment.name} runs PHP {php_branch} on platform version {platform_version}, below the minimum fixed platform version {min_platform_version}."
            else:
                report.status = "PASS"
                report.status_extended = f"Elastic Beanstalk environment {environment.name} runs PHP {php_branch} on platform version {platform_version}, which includes the fixed PHP release."

            findings.append(report)

        return findings
