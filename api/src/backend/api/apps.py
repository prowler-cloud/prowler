import logging
import os

from pathlib import Path

from django.apps import AppConfig
from django.conf import settings

from config.custom_logging import BackendLogger
from config.env import env

logger = logging.getLogger(BackendLogger.API)

SIGNING_KEY_ENV = "DJANGO_TOKEN_SIGNING_KEY"
VERIFYING_KEY_ENV = "DJANGO_TOKEN_VERIFYING_KEY"

SIGNING_KEY_FILE = "jwt_signing_key.pem"
VERIFYING_KEY_FILE = "jwt_verifying_key.pem"

KEYS_DIRECTORY = (
    Path.home() / ".keys" / "prowler-api"
)  # `/home/prowler/.keys/prowler-api` inside the container

_keys_initialized = False  # Flag to prevent multiple executions within the same process


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from api import signals  # noqa: F401
        from api.compliance import load_prowler_compliance

        self._ensure_crypto_keys()  # Generate required cryptographic keys if not present
        load_prowler_compliance()

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
        if hasattr(settings, "TESTING") and settings.TESTING:
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

    def _write_key_file(self, file_name, content):
        """
        Utility method to write content to a file.
        """
        file_path = KEYS_DIRECTORY / file_name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)

    def _ensure_jwt_keys(self):
        """
        Generate RSA key pairs for JWT token signing and verification
        if they are not already set in environment variables.
        """
        # Read existing keys from files if they exist
        signing_key = self._read_key_file(SIGNING_KEY_FILE)
        verifying_key = self._read_key_file(VERIFYING_KEY_FILE)

        if not signing_key or not verifying_key:
            # Generate and store the RSA key pair
            signing_key, verifying_key = self._generate_jwt_keys()
            self._write_key_file(SIGNING_KEY_FILE, signing_key)
            self._write_key_file(VERIFYING_KEY_FILE, verifying_key)
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
            private_key = rsa.generate_private_key(
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
