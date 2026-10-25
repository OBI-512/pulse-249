import os

from app.observability.logging import configure_operational_logging

from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
configure_operational_logging()

celery_app = Celery(
    "fttw",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.discovery", "app.tasks.recycle_bin", "app.tasks.restore_points", "app.tasks.restore_control", "app.tasks.operational_logs", "app.tasks.availability", "app.tasks.notifications", "app.tasks.telemetry", "app.tasks.data_lifecycle", "app.tasks.reports", "app.tasks.integrations", "app.tasks.configuration", "app.tasks.configuration_batches"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_hijack_root_logger=False,
    task_time_limit=900,
    task_soft_time_limit=840,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "purge-expired-recycle-bin-batches": {
            "task": "fttw.recycle_bin.purge_expired",
            "schedule": 3600.0,
            "options": {"expires": 3300},
        },
        # The task evaluates the explicit configured timezone/schedule and
        # persists its own duplicate guard. Beat remains a dedicated process.
        "cleanup-expired-restore-points": {
            "task": "fttw.restore_points.cleanup_expired",
            "schedule": 3600.0,
            "options": {"expires": 3300},
        },
        "cleanup-operational-logs": {
            "task": "fttw.operational_logs.cleanup",
            "schedule": 86400.0,
            "options": {"expires": 82800},
        },
        "evaluate-automatic-restore-points": {
            "task": "fttw.restore_points.create_automatic",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
        "dispatch-device-availability": {
            "task": "fttw.availability.dispatch_due",
            "schedule": 1.0,
            "options": {"expires": 1},
        },
        "reconcile-device-availability": {
            "task": "fttw.availability.reconcile",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
        "availability-worker-heartbeat": {
            "task": "fttw.availability.worker_heartbeat",
            "schedule": 15.0,
            "options": {"expires": 12},
        },
        "dispatch-alarm-notifications": {
            "task": "fttw.notifications.dispatch_due",
            "schedule": 5.0,
            "options": {"expires": 4},
        },
        "dispatch-device-telemetry": {
            "task": "fttw.telemetry.dispatch_due",
            "schedule": 5.0,
            "options": {"expires": 4},
        },
        "reconcile-device-telemetry": {
            "task": "fttw.telemetry.reconcile",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
        "phase-d-data-lifecycle": {
            "task": "fttw.data_lifecycle.run",
            "schedule": 3600.0,
            "options": {"expires": 3300},
        },
        "dispatch-scheduled-reports": {
            "task": "fttw.reports.dispatch_schedules",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
        "dispatch-queued-reports": {
            "task": "fttw.reports.dispatch_queued",
            "schedule": 10.0,
            "options": {"expires": 8},
        },
        "dispatch-report-deliveries": {
            "task": "fttw.reports.dispatch_deliveries",
            "schedule": 30.0,
            "options": {"expires": 25},
        },
        "reconcile-external-integrations": {
            "task": "fttw.integrations.reconcile_due",
            "schedule": 60.0,
            "options": {"expires": 55},
        },
        # F3 batch sweep emits only durable orchestration passes. Per-device
        # execution remains delegated to the existing isolated configuration queue.
        "dispatch-configuration-batches": {
            "task": "fttw.configuration.batch.sweep",
            "schedule": 5.0,
            "options": {"expires": 4, "queue": "configuration"},
        },
    },
    task_routes={
        "fttw.restore_points.execute_restore": {"queue": "restore_control"},
        "fttw.configuration.execute": {"queue": "configuration"},
        "fttw.configuration.batch.dispatch": {"queue": "configuration"},
        "fttw.configuration.batch.reconcile": {"queue": "configuration"},
        "fttw.configuration.batch.sweep": {"queue": "configuration"},
    },
)
