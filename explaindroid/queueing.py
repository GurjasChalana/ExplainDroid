from . import config


def enqueue_analysis(job_id):
    if not config.REDIS_URL:
        return {"queued": False, "reason": "REDIS_URL is not configured"}

    try:
        from redis import Redis
        from rq import Queue
    except ImportError as exc:
        raise RuntimeError("Install redis and rq to use the analysis queue") from exc

    redis_conn = Redis.from_url(config.REDIS_URL)
    queue = Queue(config.QUEUE_NAME, connection=redis_conn)
    queue.enqueue(
        "explaindroid.worker.analyze_job",
        job_id,
        job_timeout=config.ANALYSIS_TIMEOUT_SECONDS + 300,
        failure_ttl=86400,
        result_ttl=86400,
    )
    return {"queued": True}
