import json
import os
import subprocess
from typing import List

from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    load_and_validate_config_file,
)
from prowler.lib.check.models import CheckReportLLM
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class LlmProvider(Provider):
    _type: str = "llm"
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        model_type: str = "openai",
        model_name: str = "gpt-4o",
        probes: list[str] = [
            "promptinject.HijackLongPrompt",
            "promptinject.HijackKillHumans",
            "latentinjection.LatentJailbreak",
            "latentinjection.LatentInjectionReport",
            "encoding.InjectBase64",
            "encoding.InjectHex",
            "encoding.InjectROT13",
            "exploitation.JinjaTemplatePythonInjection",
            "xss.MarkdownImageExfil",
            "xss.MdExfil20230929",
            "ansiescape.AnsiEscaped",
            "suffix.GCGCached",
        ],
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
    ):
        logger.info("Instantiating LLM Provider...")

        self.model_type = model_type
        self.model_name = model_name
        self.probes = probes
        self.region = "global"
        self.audited_account = "local-llm"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist (not needed for LLM since Garak has its own logic)
        self._mutelist = None

        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=self.audited_account,
            account_name="llm",
            region=self.region,
            services_scanned=0,  # LLM doesn't use services
            expected_checks=[],  # LLM doesn't use checks
            completed_checks=0,  # LLM doesn't use progress tracking
            audit_progress=0,  # LLM doesn't use progress tracking
        )

        # Set this provider as the global provider
        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        return self._auth_method

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    def setup_session(self):
        """LLM provider doesn't need a session since it uses Garak directly"""

    def _process_check(self, finding: dict, check: dict, status: str) -> CheckReportLLM:
        """Process a Garak finding and convert it to a CheckReportLLM"""
        try:
            probe_name = finding.get("probe", "unknown_probe")
            detector = finding.get("detector_triggered", "unknown_detector")

            check_id = probe_name
            check_title = f"Garak Vulnerability Detected by Probe: {probe_name}"

            prompt = finding.get("prompt", "No prompt available.")
            llm_output = finding.get("output", "No output available.")
            description = (
                f"The probe '{probe_name}' detected a potential vulnerability "
                f"triggered by the detector '{detector}'.\n\n"
                f"Prompt Sent:\n---\n{prompt}\n---\n\n"
                f"LLM Output:\n---\n{llm_output}\n---"
            )

            resource = f"{self.model_type}:{self.model_name}"

            severity = "MEDIUM"

            return CheckReportLLM(
                check_id=check_id,
                check_title=check_title,
                check_type="LLM Security",
                status=status,
                severity=severity,
                description=description,
                resource=resource,
                file_path=self.audited_account,
                line_number=0,
                check_output=json.dumps(finding, indent=2),
                audit_metadata=self.audit_metadata,
            )
        except Exception as error:
            logger.error(f"Error processing check: {error}")
            return None

    def run(self) -> List[CheckReportLLM]:
        """Main method to run the LLM security scan"""
        try:
            return self.run_scan()
        except Exception as error:
            logger.error(f"Error running LLM scan: {error}")
            return []

    def run_scan(self) -> List[CheckReportLLM]:
        """Run Garak scan and stream its output in real-time."""
        report_path = None
        try:
            logger.info(
                f"Running LLM security scan with {self.model_type}:{self.model_name} ..."
            )

            garak_command = [
                "garak",
                "--model_type",
                self.model_type,
                "--model_name",
                self.model_name,
                "--probes",
                ",".join(self.probes),
                "--narrow_output",
                "--parallel_attempts",
                "10",
                "--parallel_requests",
                "10",
            ]

            logger.info(f"Running Garak command: {' '.join(garak_command)}")

            process = subprocess.Popen(
                garak_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=os.environ,
            )

            output_lines = []
            for line in process.stdout:
                print(line, end="", flush=True)

                output_lines.append(line)

            process.wait()
            stderr = process.stderr.read()

            if stderr:
                logger.error(f"Garak stderr:\n{stderr}")

            stdout = "".join(output_lines)

            for line in stdout.splitlines():
                if "reporting to" in line:
                    report_path = line.split("reporting to ")[1].strip()
                    logger.info(f"\nGarak report file found at: {report_path}")
                    break

            if not report_path:
                logger.critical(
                    "Could not find Garak report file path in stdout. Aborting."
                )
                if "No evaluations to report" in stdout:
                    logger.warning("Garak reported no evaluations.")
                if process.returncode != 0:
                    logger.error(
                        f"Garak exited with a non-zero exit code: {process.returncode}"
                    )
                return []

            reports = []
            with open(report_path, "r", encoding="utf-8") as report_file:
                json_lines = report_file.readlines()
                if not json_lines:
                    logger.warning(
                        "No findings returned from Garak scan (report file was empty)."
                    )
                    return []

                for line in json_lines:
                    try:
                        finding = json.loads(line)
                        print(finding)
                        break
                        if finding.get("status") == "FAIL":
                            report = self._process_check(finding, finding, "FAIL")
                            if report:
                                reports.append(report)
                    except json.JSONDecodeError as json_error:
                        logger.error(
                            f"Error decoding JSON line: {json_error} - Line content: {line.strip()}"
                        )

            return reports

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            return []
        finally:
            if report_path and os.path.exists(report_path):
                os.remove(report_path)
                logger.info(f"Cleaned up Garak report file: {report_path}")

    def print_credentials(self):
        """Print the LLM provider credentials and configuration"""
        report_title = f"{Style.BRIGHT}Scanning LLM:{Style.RESET_ALL}"
        report_lines = [
            f"Model type: {Fore.YELLOW}{self.model_type}{Style.RESET_ALL}",
            f"Model name: {Fore.YELLOW}{self.model_name}{Style.RESET_ALL}",
            f"Probes: {Fore.YELLOW}{', '.join(self.probes)}{Style.RESET_ALL}",
        ]

        print_boxes(report_lines, report_title)
