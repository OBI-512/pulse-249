from app.celery_app.config import celery_app
import logging

# Import task module so registration is deterministic.
import app.tasks.discovery  # noqa: F401
import app.tasks.recycle_bin  # noqa: F401
import app.tasks.restore_points  # noqa: F401
import app.tasks.operational_logs  # noqa: F401
import app.tasks.availability  # noqa: F401
import app.tasks.notifications  # noqa: F401
import app.tasks.telemetry  # noqa: F401
import app.tasks.data_lifecycle  # noqa: F401
import app.tasks.reports  # noqa: F401

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    logger.info("worker_started", extra={"event": "WORKER_STARTED"})
    celery_app.worker_main(
        argv=[
            "worker",
            "--loglevel=INFO",
            "--concurrency=4",
        ]
    )
