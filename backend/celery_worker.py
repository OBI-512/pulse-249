from app.celery_app.config import celery_app

# Import task module so task registration is deterministic.
import app.tasks.discovery  # noqa: F401

if __name__ == "__main__":
    celery_app.worker_main(
        argv=[
            "worker",
            "--loglevel=INFO",
            "--concurrency=4",
        ]
    )
