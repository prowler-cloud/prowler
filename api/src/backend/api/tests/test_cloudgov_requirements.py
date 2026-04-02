from pathlib import Path


class TestCloudgovBuildpackRequirements:
    def test_celery_runtime_includes_redis_client(self):
        requirements_path = Path(__file__).resolve().parents[4] / "requirements.txt"
        requirements = requirements_path.read_text().splitlines()

        assert any(requirement.startswith("redis==") for requirement in requirements)

    def test_worker_script_uses_cloudgov_safe_celery_defaults(self):
        script_path = Path(__file__).resolve().parents[4] / "bin" / "cloudgov-worker.sh"
        script = script_path.read_text()

        assert '--pool "${CELERY_WORKER_POOL:-solo}"' in script
        assert '--concurrency "${CELERY_WORKER_CONCURRENCY:-1}"' in script

    def test_manifest_allocates_extra_memory_for_beat(self):
        manifest_path = Path(__file__).resolve().parents[5] / "manifest.yml"
        manifest = manifest_path.read_text()

        assert "- name: prowler-api-beat" in manifest
        assert "memory: 512M" in manifest

    def test_web_script_only_runs_migrations_when_enabled(self):
        script_path = Path(__file__).resolve().parents[4] / "bin" / "cloudgov-web.sh"
        script = script_path.read_text()

        assert 'if [[ "${RUN_DB_MIGRATIONS:-0}" == "1" ]]; then' in script
        assert "python manage.py migrate" in script

    def test_manifest_disables_web_boot_migrations(self):
        manifest_path = Path(__file__).resolve().parents[5] / "manifest.yml"
        manifest = manifest_path.read_text()

        assert "RUN_DB_MIGRATIONS: 0" in manifest