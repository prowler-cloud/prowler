import json
import os
import subprocess
import sys
from typing import List

import yaml
from alive_progress import alive_bar
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    default_redteam_config_file_path,
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
    model: str = ""

    def __init__(
        self,
        max_concurrency: int = 10,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
    ):
        logger.info("Instantiating LLM Provider...")
        logger.info(f"Received config_path: {config_path}")

        self.max_concurrency = max_concurrency
        # For LLM provider, only use config_path if it's not the default Prowler config
        if config_path and config_path != default_config_file_path:
            self.config_path = config_path
        else:
            self.config_path = default_redteam_config_file_path

        # Read config file and extract model
        with open(self.config_path, "r") as config_file:
            config = yaml.safe_load(config_file)
            self.model = config.get("targets", [])[0].get("id", "No model available.")
            # Extract only the plugin IDs
            plugins_data = config.get("redteam", {}).get("plugins", [])
            self.plugins = [
                plugin.get("id") for plugin in plugins_data if plugin.get("id")
            ]
        self.region = "global"
        self.audited_account = "local-llm"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"

        # Audit Config
        if config_content:
            self._audit_config = config_content
        elif self.config_path:
            self._audit_config = load_and_validate_config_file(
                self._type, self.config_path
            )
        else:
            # For LLM provider, use empty config if no config file provided
            self._audit_config = {}

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist (not needed for LLM since promptfoo has its own logic)
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

    @property
    def auth_method(self):
        return self._auth_method

    def setup_session(self):
        """LLM provider doesn't need a session since it uses promptfoo directly"""

    def _process_check(self, finding: dict) -> CheckReportLLM:
        """
        Process a single check (failed or passed) and create a CheckReportIAC object.

        Args:
            finding: The finding object from Trivy output
            file_path: The path to the file that contains the finding
            type: The type of the finding

        Returns:
            CheckReportIAC: The processed check report
        """
        try:
            status = "FAIL"
            if finding.get("success"):
                status = "PASS"

            metadata_dict = {
                "Provider": "llm",
                "CheckID": finding["metadata"]["pluginId"],
                "CheckTitle": finding["metadata"]["goal"],
                "CheckType": ["LLM Security"],
                "ServiceName": finding["metadata"]["pluginId"].split(":")[0],
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": finding["metadata"]["severity"].lower(),
                "ResourceType": "llm",
                "Description": finding["metadata"]["goal"],
                "Risk": "",
                "RelatedUrl": "",
                "Remediation": {
                    "Code": {
                        "NativeIaC": "",
                        "Terraform": "",
                        "CLI": "",
                        "Other": "",
                    },
                    "Recommendation": {
                        "Text": "",
                        "Url": "",
                    },
                },
                "Categories": [],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Convert metadata dict to JSON string
            metadata = json.dumps(metadata_dict)

            report = CheckReportLLM(
                metadata=metadata,
                finding=finding,
            )
            report.status = status
            status_extended = (
                finding.get("gradingResult", {})
                .get("componentResults", [{}])[0]
                .get("reason", "No assertions found.")
            )
            report.status_extended = status_extended
            return report
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _process_finding_line(
        self, line: str, reports: list, streaming_callback=None, progress_counter=None
    ) -> bool:
        """
        Process a single line from the report file and add to reports if valid.

        Args:
            line: JSON line from the report file
            reports: List to append the processed report to
            streaming_callback: Optional callback for streaming mode
            progress_counter: Optional dict to track progress {'completed': int, 'total': int, 'completed_test_ids': set}

        Returns:
            bool: True if a valid finding was processed, False otherwise
        """
        try:
            finding = json.loads(line.strip())
            # Extract testIdx and track unique tests
            test_idx = finding.get("testIdx")
            if test_idx is not None and progress_counter is not None:
                if test_idx not in progress_counter["completed_test_ids"]:
                    progress_counter["completed_test_ids"].add(test_idx)
                    progress_counter["completed"] += 1
            if finding.get("prompt", {}).get("raw"):
                if finding.get("response", {}).get("error"):
                    logger.error(f"Error: {finding.get('response', {}).get('error')}")
                    return False
                elif finding.get("error"):
                    logger.error(f"{finding.get('error')}")
                    return False
                report = self._process_check(finding)
                if report:
                    reports.append(report)
                    if streaming_callback:
                        streaming_callback([report])
                    return True
        except json.JSONDecodeError as json_error:
            logger.error(
                f"Error decoding JSON line: {json_error} - Line content: {line.strip()}"
            )
        return False

    def run(self) -> List[CheckReportLLM]:
        """Main method to run the LLM security scan"""
        try:
            return self.run_scan()
        except Exception as error:
            logger.error(f"Error running LLM scan: {error}")
            return []

    def run_scan(self, streaming_callback) -> List[CheckReportLLM]:
        """Run promptfoo red team scan and process its output."""
        report_path = None
        try:
            logger.info("Running LLM security scan...")

            # Use config file if provided, otherwise let promptfoo use its defaults
            if self.config_path:
                if not os.path.exists(self.config_path):
                    logger.error(f"Config file not found: {self.config_path}")
                    return []
                config_path = self.config_path
                logger.info(f"Using provided config file: {config_path}")

            # Set output path for the scan results
            report_path = "/tmp/prowler_promptfoo_results.jsonl"

            promptfoo_command = [
                "promptfoo",
                "redteam",
                "eval",
                "--output",
                report_path,
                "--max-concurrency",
                str(self.max_concurrency),
                "--no-cache",
                "--config",
                config_path,
            ]

            logger.info(f"Running promptfoo command: {' '.join(promptfoo_command)}")

            process = subprocess.Popen(
                promptfoo_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=os.environ,
            )

            return self._stream_findings(process, report_path, streaming_callback)

        except Exception as error:
            if "No such file or directory: 'promptfoo'" in str(error):
                logger.critical(
                    "Promptfoo binary not found. Please install promptfoo from https://promptfoo.dev/docs/installation/ or use your system package manager (e.g., 'npm install -g promptfoo' or 'brew install promptfoo' on macOS)"
                )
                sys.exit(1)
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            return []
        finally:
            # Clean up temporary report file
            if report_path and os.path.exists(report_path):
                os.remove(report_path)
                logger.info(f"Cleaned up promptfoo report file: {report_path}")

    def _stream_findings(self, process, report_path, streaming_callback):
        """Stream findings in real-time as they are written to the output file."""
        import queue
        import re
        import threading
        import time

        reports = []
        processed_lines = set()  # Track which lines we've already processed
        error_queue = queue.Queue()  # Thread-safe communication for errors

        def monitor_file():
            """Monitor the output file for new findings."""
            try:
                while process.poll() is None:  # While process is still running
                    if os.path.exists(report_path):
                        try:
                            with open(
                                report_path, "r", encoding="utf-8"
                            ) as report_file:
                                lines = report_file.readlines()

                                # Process only new lines
                                for i, line in enumerate(lines):
                                    if i not in processed_lines and line.strip():
                                        if self._process_finding_line(
                                            line,
                                            reports,
                                            streaming_callback,
                                            progress_counter,
                                        ):
                                            processed_lines.add(i)
                        except Exception as e:
                            logger.debug(f"Error reading report file: {e}")

                    time.sleep(0.5)  # Check every 500ms
            except Exception as e:
                logger.debug(f"Monitor file thread error: {e}")

        def process_stdout(error_queue):
            """Process stdout to extract test count information and detect errors."""
            try:
                for line in process.stdout:
                    if (
                        "Redteam evals require email verification. Please enter your work email"
                        in line
                    ):
                        error_queue.put(
                            "Please, provide first your work email in promptfoo with  `promptfoo config set email <email>` command."
                        )
                        process.terminate()
                        return
                    if "No promptfooconfig found" in line:
                        error_queue.put(
                            "No config file found. Please, provide a valid promptfoo config file."
                        )
                        process.terminate()
                        return
                    if (
                        "Warning: Config file has a redteam section but no test cases."
                        in line
                    ):
                        error_queue.put(
                            "Please, generate first the test cases using `promptfoo redteam generate` command."
                        )
                        process.terminate()
                        return

                    # Extract total number of tests from stdout
                    test_count_match = re.search(
                        r"Running (\d+) test cases \(up to \d+ at a time\)", line
                    )
                    if test_count_match and progress_counter["total"] == 0:
                        progress_counter["total"] = int(test_count_match.group(1))
                        logger.info(
                            f"Found {progress_counter['total']} test cases to run"
                        )
            except Exception as e:
                logger.debug(f"Process stdout thread error: {e}")

        # Create progress counter dictionary
        progress_counter = {"completed": 0, "total": 0, "completed_test_ids": set()}
        previous_completed = 0  # Track previous completed count for bar updates

        # Start monitoring in separate threads
        monitor_thread = threading.Thread(target=monitor_file)
        monitor_thread.daemon = True
        monitor_thread.start()

        stdout_thread = threading.Thread(target=process_stdout, args=(error_queue,))
        stdout_thread.daemon = True
        stdout_thread.start()

        # Wait for total number of tests to be detected or error
        while process.poll() is None and progress_counter["total"] == 0:
            # Check for errors from background thread
            try:
                error_msg = error_queue.get_nowait()
                logger.critical(error_msg)
                process.terminate()
                process.wait()  # Ensure cleanup
                sys.exit(1)
            except queue.Empty:
                pass

            time.sleep(0.5)  # Wait for total to be detected

        # If process finished before we detected total, handle it
        if process.poll() is not None and progress_counter["total"] == 0:
            # Check for any final errors
            try:
                error_msg = error_queue.get_nowait()
                logger.critical(error_msg)
                sys.exit(1)
            except queue.Empty:
                pass

            process.wait()
            logger.critical(
                f"Promptfoo exited with a non-zero exit code {process.returncode} {process.stderr.read()}"
            )
            sys.exit(1)

        # Now create the progress bar with the known total
        with alive_bar(
            total=progress_counter["total"],
            ctrl_c=False,
            bar="blocks",
            spinner="classic",
            stats=False,
            enrich_print=False,
        ) as bar:
            try:
                bar.title = f"-> Running LLM security scan on {self.model}..."

                # Update progress bar while process is running
                while process.poll() is None:
                    # Check for errors from background thread during execution
                    try:
                        error_msg = error_queue.get_nowait()
                        logger.critical(error_msg)
                        process.terminate()
                        process.wait()  # Ensure cleanup
                        bar.title = "-> LLM security scan failed!"
                        sys.exit(1)
                    except queue.Empty:
                        pass

                    # Update the progress by incrementing by the difference
                    if progress_counter["completed"] > previous_completed:
                        bar(progress_counter["completed"] - previous_completed)
                        previous_completed = progress_counter["completed"]

                    time.sleep(0.5)  # Update every 500ms

                # Wait for process to complete
                process.wait()

                # Wait a bit more for any final findings to be written
                time.sleep(1)

                # Process any remaining findings
                if os.path.exists(report_path):
                    try:
                        with open(report_path, "r", encoding="utf-8") as report_file:
                            lines = report_file.readlines()
                            for i, line in enumerate(lines):
                                if i not in processed_lines and line.strip():
                                    self._process_finding_line(
                                        line,
                                        reports,
                                        streaming_callback,
                                        progress_counter,
                                    )
                    except Exception as e:
                        logger.error(f"Error processing final findings: {e}")

                bar.title = "-> LLM security scan completed!"

            except Exception as error:
                bar.title = "-> LLM security scan failed!"
                raise error

        # Check for errors
        stderr = process.stderr.read()
        if stderr:
            logger.error(f"Promptfoo stderr:\n{stderr}")

        if (
            process.returncode != 0
            and process.returncode != 100
            and process.returncode is not None
            and process.returncode != -2
        ):
            logger.error(
                f"Promptfoo exited with a non-zero exit code: {process.returncode}"
            )
            sys.exit(1)

        return reports

    def print_credentials(self):
        """Print the LLM provider credentials and configuration"""
        report_title = f"{Style.BRIGHT}Scanning LLM:{Style.RESET_ALL}"
        report_lines = [
            f"Target LLM: {Fore.YELLOW}{self.model}{Style.RESET_ALL}",
        ]
        if self.plugins:
            report_lines.append(
                f"Plugins: {Fore.YELLOW}{', '.join(self.plugins)}{Style.RESET_ALL}"
            )
        if self.config_path:
            report_lines.append(
                f"Config file: {Fore.YELLOW}{self.config_path}{Style.RESET_ALL}"
            )
        else:
            report_lines.append("Using promptfoo default configuration")

        report_lines.append(
            f"Max concurrency: {Fore.YELLOW}{self.max_concurrency}{Style.RESET_ALL}"
        )

        print_boxes(report_lines, report_title)
