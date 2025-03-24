from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client

<<<<<<< HEAD
=======
default_obsolete_lambda_runtimes = [
    "java8",
    "go1.x",
    "provided",
    "python3.6",
    "python2.7",
    "python3.7",
    "python3.8",
    "nodejs4.3",
    "nodejs4.3-edge",
    "nodejs6.10",
    "nodejs",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "dotnet5.0",
    "dotnet6",
    "dotnet7",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "ruby2.5",
    "ruby2.7",
]

>>>>>>> 9923def4c (chore(awslambda): update obsolete lambda runtimes (#7330))

class awslambda_function_using_supported_runtimes(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            if function.runtime:
                report = Check_Report_AWS(self.metadata())
                report.region = function.region
                report.resource_id = function.name
                report.resource_arn = function.arn
                report.resource_tags = function.tags

                if function.runtime in awslambda_client.audit_config.get(
                    "obsolete_lambda_runtimes", []
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Lambda function {function.name} is using {function.runtime} which is obsolete."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {function.name} is using {function.runtime} which is supported."

                findings.append(report)

        return findings
