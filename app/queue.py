import os
import json
from redis import Redis
from rq import Queue

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

redis_conn = Redis.from_url(REDIS_URL)
scan_queue = Queue("scans", connection=redis_conn)


def enqueue_scan(scan_id: int, targets: list, ports: str, protocol: str):
    """Enfileira job de scan. Retorna job id."""
    job = scan_queue.enqueue(
        "app.worker.process_scan",
        scan_id,
        targets,
        ports,
        protocol,
        job_timeout=300,
        result_ttl=3600,
    )
    return job.id
