import logging
import os
import sys
from pathlib import Path

from config.custom_logging import BackendLogger
from config.env import env
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(BackendLogger.API)

SIGNING_KEY_ENV = "DJANGO_TOKEN_SIGNING_KEY"
VERIFYING_KEY_ENV = "DJANGO_TOKEN_VERIFYING_KEY"

PRIVATE_KEY_FILE = "jwt_private.pem"
PUBLIC_KEY_FILE = "jwt_public.pem"

KEYS_DIRECTORY = (
    Path.home() / ".config" / "prowler-api"
)  # `/home/prowler/.config/prowler-api` inside the container

_keys_initialized = False  # Flag to prevent multiple executions within the same process


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from api import schema_extensions  # noqa: F401
        from api import signals  # noqa: F401
        from api.attack_paths import database as graph_database

        # Generate required cryptographic keys if not present, but only if:
        #   `"manage.py" not in sys.argv[0]`: If an external server (e.g., Gunicorn) is running the app
        #   `os.environ.get("RUN_MAIN")`: If it's not a Django command or using `runserver`,
        #                                 only the main process will do it
        if (len(sys.argv) >= 1 and "manage.py" not in sys.argv[0]) or os.environ.get(
            "RUN_MAIN"
        ):
            self._ensure_crypto_keys()

        # Commands that don't need Neo4j
        SKIP_NEO4J_DJANGO_COMMANDS = [
            "makemigrations",
            "migrate",
            "pgpartition",
            "check",
            "help",
            "showmigrations",
            "check_and_fix_socialaccount_sites_migration",
        ]

        # Skip Neo4j initialization during tests, some Django commands, and Celery
        if getattr(settings, "TESTING", False) or (
            len(sys.argv) > 1
            and (
                (
                    "manage.py" in sys.argv[0]
                    and sys.argv[1] in SKIP_NEO4J_DJANGO_COMMANDS
                )
                or "celery" in sys.argv[0]
            )
        ):
            logger.info(
                "Skipping Neo4j initialization because tests, some Django commands or Celery"
            )

        else:
            graph_database.init_driver()

        # Neo4j driver is initialized at API startup (see api.attack_paths.database)
        # It remains lazy for Celery workers and selected Django commands

    def _ensure_crypto_keys(self):
        """
        Orchestrator method that ensures all required cryptographic keys are present.
        This method coordinates the generation of:
          - RSA key pairs for JWT token signing and verification
        Note: During development, Django spawns multiple processes (migrations, fixtures, etc.)
        which will each generate their own keys. This is expected behavior and each process
        will have consistent keys for its lifetime. In production, set the keys as environment
        variables to avoid regeneration.
        """
        global _keys_initialized

        # Skip key generation if running tests
        if getattr(settings, "TESTING", False):
            return

        # Skip if already initialized in this process
        if _keys_initialized:
            return

        # Check if both JWT keys are set; if not, generate them
        signing_key = env.str(SIGNING_KEY_ENV, default="").strip()
        verifying_key = env.str(VERIFYING_KEY_ENV, default="").strip()

        if not signing_key or not verifying_key:
            logger.info(
                f"Generating JWT RSA key pair. In production, set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' "
                "environment variables."
            )
            self._ensure_jwt_keys()

        # Mark as initialized to prevent future executions in this process
        _keys_initialized = True

    def _read_key_file(self, file_name):
        """
        Utility method to read the contents of a file.
        """
        file_path = KEYS_DIRECTORY / file_name
        return file_path.read_text().strip() if file_path.is_file() else None

    def _write_key_file(self, file_name, content, private=True):
        """
        Utility method to write content to a file.
        """
        try:
            file_path = KEYS_DIRECTORY / file_name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            file_path.chmod(0o600 if private else 0o644)

        except Exception as e:
            logger.error(
                f"Error writing key file '{file_name}': {e}. "
                f"Please set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' manually."
            )
            raise e

    def _ensure_jwt_keys(self):
        """
        Generate RSA key pairs for JWT token signing and verification
        if they are not already set in environment variables.
        """
        # Read existing keys from files if they exist
        signing_key = self._read_key_file(PRIVATE_KEY_FILE)
        verifying_key = self._read_key_file(PUBLIC_KEY_FILE)

        if not signing_key or not verifying_key:
            # Generate and store the RSA key pair
            signing_key, verifying_key = self._generate_jwt_keys()
            self._write_key_file(PRIVATE_KEY_FILE, signing_key, private=True)
            self._write_key_file(PUBLIC_KEY_FILE, verifying_key, private=False)
            logger.info("JWT keys generated and stored successfully")

        else:
            logger.info("JWT keys already generated")

        # Set environment variables and Django settings
        os.environ[SIGNING_KEY_ENV] = signing_key
        settings.SIMPLE_JWT["SIGNING_KEY"] = signing_key

        os.environ[VERIFYING_KEY_ENV] = verifying_key
        settings.SIMPLE_JWT["VERIFYING_KEY"] = verifying_key

    def _generate_jwt_keys(self):
        """
        Generate and set RSA key pairs for JWT token operations.
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            # Generate RSA key pair
            private_key = rsa.generate_private_key(  # Future improvement: we could read the next values from env vars
                public_exponent=65537,
                key_size=2048,
            )

            # Serialize private key (for signing)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            # Serialize public key (for verification)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            logger.debug("JWT RSA key pair generated successfully.")
            return private_pem, public_pem

        except ImportError as e:
            logger.warning(
                "The 'cryptography' package is required for automatic JWT key generation."
            )
            raise e

        except Exception as e:
            logger.error(
                f"Error generating JWT keys: {e}. Please set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' manually."
            )
            raise e
