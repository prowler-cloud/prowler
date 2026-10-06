import hashlib
import logging
import os
import sys
import time
from pathlib import Path

from config.custom_logging import BackendLogger
from config.env import env
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(BackendLogger.API)

SIGNING_KEY_ENV = "DJANGO_TOKEN_SIGNING_KEY"
VERIFYING_KEY_ENV = "DJANGO_TOKEN_VERIFYING_KEY"
ENCRYPTION_KEY_ENV = "DJANGO_SECRETS_ENCRYPTION_KEY"
SECRET_KEY_ENV = "SECRET_KEY"

PRIVATE_KEY_FILE = "jwt_private.pem"
PUBLIC_KEY_FILE = "jwt_public.pem"
ENCRYPTION_KEY_FILE = "secrets_encryption.key"
SECRET_KEY_FILE = "django_secret.key"

KEYS_DIRECTORY = (
    Path.home() / ".config" / "prowler-api"
)  # `/home/prowler/.config/prowler-api` inside the container

# SHA-256 of encryption keys that were committed to this repository with a working
# value. They are public, so a deployment still using one of them must rotate.
PUBLISHED_ENCRYPTION_KEY_DIGESTS = frozenset(
    {
        # Root `.env` shipped to self-hosted installs until this check was added
        "a9c1d15afaddc1753245e48117f7c80525973a4f64179d447a843ca372c0ba0e",
        # contrib/k8s/helm/prowler-app/examples/minimal-installation/secrets.yaml
        "c7576d54c7120bab3a486d44a7a8640907cc28eaeec6bc41f4aa2e95ad407015",
    }
)

ENCRYPTION_KEY_DOCS = (
    "https://docs.prowler.com/getting-started/installation/prowler-app"
    "#secrets-encryption-key"
)

_keys_initialized = False  # Flag to prevent multiple executions within the same process


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def import_models(self):
        # `api.models` builds its Fernet instance at import time, so the encryption
        # key has to be settled before Django loads this app's models.
        self._ensure_secrets()
        super().import_models()

    def ready(self):
        from api import (
            schema_extensions,  # noqa: F401
            signals,  # noqa: F401
        )

        # Generate required cryptographic keys if not present, but only if:
        #   `"manage.py" not in sys.argv[0]`: If an external server (e.g., Gunicorn) is running the app
        #   `os.environ.get("RUN_MAIN")`: If it's not a Django command or using `runserver`,
        #                                 only the main process will do it
        if (len(sys.argv) >= 1 and "manage.py" not in sys.argv[0]) or os.environ.get(
            "RUN_MAIN"
        ):
            self._ensure_crypto_keys()

    def _ensure_secrets(self):
        """
        Settle the symmetric secrets every process needs before the models load:
          - `DJANGO_SECRETS_ENCRYPTION_KEY`, the Fernet key protecting stored credentials
          - `SECRET_KEY`, Django's signing key
        Both are generated and persisted under `KEYS_DIRECTORY` when empty. An
        encryption key that was ever published with this repository is refused.
        """
        if getattr(settings, "TESTING", False):
            return

        self._ensure_encryption_key()
        self._ensure_secret_key()

    def _ensure_encryption_key(self):
        key = (getattr(settings, "SECRETS_ENCRYPTION_KEY", "") or "").strip()

        if key:
            if _digest(key) in PUBLISHED_ENCRYPTION_KEY_DIGESTS:
                raise ImproperlyConfigured(
                    f"'{ENCRYPTION_KEY_ENV}' is set to a value that was published in the "
                    "Prowler repository and is therefore public. Generate a new key, "
                    f"re-enter the stored credentials and restart. See {ENCRYPTION_KEY_DOCS}"
                )
            return

        key = self._load_or_generate_secret(
            ENCRYPTION_KEY_FILE, ENCRYPTION_KEY_ENV, self._generate_encryption_key
        )

        os.environ[ENCRYPTION_KEY_ENV] = key
        settings.SECRETS_ENCRYPTION_KEY = key
        # Mutated in place: `drf_simple_apikey` keeps a reference to this dict
        settings.DRF_API_KEY["FERNET_SECRET"] = key

    def _ensure_secret_key(self):
        # Read from the environment: `settings.SECRET_KEY` raises while it is empty
        if env.str(SECRET_KEY_ENV, default="").strip():
            return

        key = self._load_or_generate_secret(
            SECRET_KEY_FILE, SECRET_KEY_ENV, self._generate_secret_key
        )

        os.environ[SECRET_KEY_ENV] = key
        settings.SECRET_KEY = key

    def _load_or_generate_secret(self, file_name, env_name, generate):
        """
        Return the secret persisted as `file_name`, generating it on first boot.
        """
        existing = self._read_key_file(file_name)
        if existing:
            return existing

        file_path = KEYS_DIRECTORY / file_name
        value = generate()

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # Another process of this deployment generated it first
            return self._wait_for_key_file(file_name, env_name)
        except OSError as e:
            logger.error(f"Cannot persist '{file_name}' under '{KEYS_DIRECTORY}': {e}")
            raise ImproperlyConfigured(
                f"'{env_name}' is empty and no value could be persisted under "
                f"'{KEYS_DIRECTORY}'. Set '{env_name}' in the environment or make the "
                "directory writable."
            ) from e

        with os.fdopen(fd, "w") as key_file:
            key_file.write(value)

        logger.warning(
            f"'{env_name}' was empty: generated '{file_name}' under '{KEYS_DIRECTORY}'. "
            "Keep that file across upgrades and back it up; losing it makes the data "
            "it protects unreadable."
        )
        return value

    def _wait_for_key_file(self, file_name, env_name):
        for _ in range(10):
            existing = self._read_key_file(file_name)
            if existing:
                return existing
            time.sleep(0.1)

        raise ImproperlyConfigured(
            f"'{env_name}' is empty and '{file_name}' under '{KEYS_DIRECTORY}' could "
            "not be read. Set the variable in the environment or remove the file."
        )

    @staticmethod
    def _generate_encryption_key():
        from cryptography.fernet import Fernet

        return Fernet.generate_key().decode()

    @staticmethod
    def _generate_secret_key():
        from django.core.management.utils import get_random_secret_key

        return get_random_secret_key()

    def _ensure_crypto_keys(self):
        """
        Orchestrator method that ensures all required cryptographic keys are present.
        This method coordinates the generation of:
          - RSA key pairs for JWT token signing and verification
        The symmetric secrets are handled earlier, in `_ensure_secrets`, because the
        models need them at import time.
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
