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
ENCRYPTION_KEY_ENV = "DJANGO_SECRETS_ENCRYPTION_KEY"

KEYS_DIRECTORY = ".keys"


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    # Flag to prevent multiple executions within the same process
    _keys_initialized = False

    def ready(self):
        from api import signals  # noqa: F401
        from api.compliance import load_prowler_compliance

        # Generate required cryptographic keys if not present
        self._ensure_crypto_keys()

        load_prowler_compliance()

    def _ensure_crypto_keys(self):
        """
        Orchestrator method that ensures all required cryptographic keys are present.
        This method coordinates the generation of:
        - RSA key pairs for JWT token signing and verification
        - Fernet encryption key for secrets encryption
        Note: During development, Django spawns multiple processes (migrations, fixtures, etc.)
        which will each generate their own keys. This is expected behavior and each process
        will have consistent keys for its lifetime. In production, set the keys as environment
        variables to avoid regeneration.
        """
        # Skip key generation if running tests
        if hasattr(settings, "TESTING") and settings.TESTING:
            return

        # Skip if already initialized in this process
        if self._keys_initialized:
            return

        # TODO: Comment
        if not all(env.str(key, default="").strip() for key in [SIGNING_KEY_ENV, VERIFYING_KEY_ENV]):
            logger.info(
                f"Generating JWT RSA key pair. In production, set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' environment variables."
            )
            self._ensure_jwt_keys()

        if not env.str(ENCRYPTION_KEY_ENV, default="").strip():
            logger.info(
                f"Generating Fernet encryption key for secrets encryption. In production, set '{ENCRYPTION_KEY_ENV}' environment variable."
            )
            self._ensure_secrets_encryption_key()

        # Mark as initialized to prevent future executions in this process
        self._keys_initialized = True


    def _read_file(self, file_path):
        """
        Utility method to read the contents of a file.
        """
        return file_path.read_text().strip() if file_path.is_file() else None


    def _write_file(self, file_path, content):
        """
        Utility method to write content to a file.
        """
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)


    def _ensure_jwt_keys(self):
        """
        Generate RSA key pairs for JWT token signing and verification
        if they are not already set in environment variables.
        """
        signing_key_file_path = Path.cwd() / KEYS_DIRECTORY / SIGNING_KEY_ENV
        verifying_key_file_path = Path.cwd() / KEYS_DIRECTORY / VERIFYING_KEY_ENV

        signing_key = self._read_file(signing_key_file_path)
        verifying_key = self._read_file(verifying_key_file_path)

        if not signing_key or not verifying_key:
            # Generate and store the RSA key pair
            signing_key, verifying_key = self._generate_jwt_keys()
            self._write_file(signing_key_file_path, signing_key)
            self._write_file(verifying_key_file_path, verifying_key)

        else:
            logger.debug("JWT keys already configured, skipping generation")

        # Set environment variables and Django settings
        os.environ[SIGNING_KEY_ENV] = signing_key
        os.environ[VERIFYING_KEY_ENV] = verifying_key
        settings.TOKEN_SIGNING_KEY = signing_key
        settings.TOKEN_VERIFYING_KEY = verifying_key

    def _ensure_secrets_encryption_key(self):
        """
        Generate Fernet encryption key for secrets encryption
        if it is not already set in environment variables.
        """
        encryption_key_file_path = Path.cwd() / KEYS_DIRECTORY / ENCRYPTION_KEY_ENV
        encryption_key = self._read_file(encryption_key_file_path)

        if not encryption_key:
            # Generate and store the encryption key
            encryption_key = self._generate_secrets_encryption_key()
            self._write_file(encryption_key_file_path, encryption_key)

        else:
            logger.debug("Fernet encryption key already configured, skipping generation")

        # Set environment variable and Django setting
        os.environ[ENCRYPTION_KEY_ENV] = encryption_key
        settings.SECRETS_ENCRYPTION_KEY = encryption_key

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
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")

            # Serialize public key (for verification)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            # Set environment variables
            os.environ[SIGNING_KEY_ENV] = private_pem
            os.environ[VERIFYING_KEY_ENV] = public_pem

            logger.debug("JWT RSA key pair generated successfully.")
            return private_pem, public_pem

        except ImportError as e:
            logger.warning("The 'cryptography' package is required for automatic JWT key generation.")
            raise e

        except Exception as e:
            logger.error(
                f"Error generating JWT keys: {e}. Please set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' manually."
            )
            raise e

    def _generate_secrets_encryption_key(self):
        """
        Generate and set Fernet encryption key for secrets encryption.
        """
        try:
            from cryptography.fernet import Fernet

            # Generate Fernet key for secrets encryption
            fernet_key = Fernet.generate_key().decode("utf-8")

            logger.debug("Fernet encryption key generated successfully for secrets encryption.")
            return fernet_key

        except ImportError as e:
            logger.warning("The 'cryptography' package is required for automatic Fernet key generation.")
            raise e

        except Exception as e:
            logger.error(f"Error generating Fernet encryption key: {e}. Please set '{ENCRYPTION_KEY_ENV}' manually.")
            raise e
