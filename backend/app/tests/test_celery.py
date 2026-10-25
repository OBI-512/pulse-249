import shlex
from pathlib import Path

import pytest
import yaml

from app.celery_app.config import celery_app
from app.tasks.configuration import execute_configuration_operation
from app.tasks.discovery import run_batch_discovery


def test_celery_app_configuration():
    assert celery_app.main == "fttw"
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_discovery_task_is_registered():
    assert "fttw.discovery.batch" in celery_app.tasks
    assert run_batch_discovery.name == "fttw.discovery.batch"


def test_availability_tasks_and_schedule_are_registered():
    from app.tasks.availability import dispatch_due_availability, poll_availability_batch, reconcile_device_availability

    assert "fttw.availability.dispatch_due" in celery_app.tasks
    assert "fttw.availability.poll_batch" in celery_app.tasks
    assert "fttw.availability.reconcile" in celery_app.tasks
    assert dispatch_due_availability.name == "fttw.availability.dispatch_due"
    assert poll_availability_batch.name == "fttw.availability.poll_batch"
    assert reconcile_device_availability.name == "fttw.availability.reconcile"
    entry = celery_app.conf.beat_schedule["dispatch-device-availability"]
    assert entry["schedule"] == 1.0
    assert entry["options"]["expires"] == 1


def test_configuration_task_is_registered_and_routed_to_dedicated_queue():
    assert "fttw.configuration.execute" in celery_app.tasks
    assert execute_configuration_operation.name == "fttw.configuration.execute"
    assert celery_app.conf.task_routes["fttw.configuration.execute"] == {
        "queue": "configuration"
    }


def test_production_compose_consumes_configuration_task_queue():
    root = Path(__file__).resolve().parents[3]
    compose_path = root / "docker-compose.prod.yml"
    if not compose_path.is_file():
        pytest.skip("Repository-level Compose file is outside the backend image build context.")

    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    worker = compose["services"]["configuration-worker"]
    command = shlex.split(worker["command"])

    queue_flag = command.index("-Q")
    assert command[queue_flag + 1] == "configuration"
    assert worker["build"]["dockerfile"] == "Dockerfile.configuration-worker.prod"
    assert worker["restart"] == "unless-stopped"
    assert set(worker["depends_on"]) == {"postgres", "redis"}
    assert set(worker["networks"]) == {"data", "management"}
    assert "ports" not in worker
