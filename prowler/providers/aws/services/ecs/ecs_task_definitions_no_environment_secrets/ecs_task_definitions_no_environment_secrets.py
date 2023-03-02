import os
import tempfile
from json import dumps

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_no_environment_secrets(Check):
    def execute(self):
        findings = []
        for task_definition in ecs_client.task_definitions:
            report = Check_Report_AWS(self.metadata())
            report.region = task_definition.region
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.resource_arn = task_definition.arn
            report.resource_tags = task_definition.tags
            report.status = "PASS"
            report.status_extended = f"No secrets found in variables of ECS task definition {task_definition.name} with revision {task_definition.revision}"
            if task_definition.environment_variables:
                dump_env_vars = {}
                for env_var in task_definition.environment_variables:
                    dump_env_vars.update({env_var.name: env_var.value})

                temp_env_data_file = tempfile.NamedTemporaryFile(delete=False)

                env_data = dumps(dump_env_vars, indent=2)
                temp_env_data_file.write(bytes(env_data, encoding="raw_unicode_escape"))
                temp_env_data_file.close()

                secrets = SecretsCollection()
                with default_settings():
                    secrets.scan_file(temp_env_data_file.name)

                detect_secrets_output = secrets.json()
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output[temp_env_data_file.name]
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in variables of ECS task definition {task_definition.name} with revision {task_definition.revision} -> {secrets_string}"

                os.remove(temp_env_data_file.name)

            findings.append(report)

        return findings
