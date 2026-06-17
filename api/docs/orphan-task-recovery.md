# Orphan Celery task recovery

When a worker is terminated mid-task (a deploy, an OOM kill, a node eviction), the
task it was running can be left non-terminal forever: the `TaskResult` stays
`STARTED` and nothing re-runs it. This page describes the mechanisms that detect and
recover allowlisted idempotent orphans so pending-task alerts do not fire. Scan tasks
are not auto-recovered (re-running a scan is not safe to do automatically); the
watchdog covers the summary/aggregation and deletion tasks.

## How recovery works

1. **Durable delivery.** The broker is configured so a task message is acknowledged
   only after the task finishes (`task_acks_late`), one task is reserved at a time
   (`worker_prefetch_multiplier = 1`), and an abruptly-lost worker re-queues its task
   (`task_reject_on_worker_lost`). On `SIGTERM` the worker is given a soft-shutdown
   window (`worker_soft_shutdown_timeout`) to finish or re-queue in-flight work
   before it is force-killed. `scan-perform`, `scan-perform-scheduled` and
   `integration-jira` opt out of redelivery with `acks_late=False`, so a crash drops
   them rather than re-running and duplicating findings or Jira issues. Other
   non-recovered side-effect tasks keep `acks_late=True`, so the broker can still
   re-deliver them after a worker loss: the S3 upload rebuilds from worker-local files
   that did not survive the crash and so no-ops, but Security Hub re-reads findings from
   the DB and re-sends them to AWS.

2. **Periodic watchdog.** A Beat task, `reconcile-orphan-tasks`, runs every couple of
   minutes (a `django_celery_beat` periodic task created by migration). For each
   in-flight task result with an allowlisted idempotent task name, it pings the
   worker recorded on the task's `TaskResult`:
   - worker responds -> the task is still running, leave it alone;
   - worker is gone (and the task started before a short grace window) -> it is a
     real orphan: the stale task is revoked and marked terminal (clearing the
     pending/started alert), and the task is re-enqueued from its stored name and
     kwargs.

   The re-run is safe because only tasks with proven idempotency are allowlisted: the
   summary/aggregation tasks clear and re-write their own rows, and deletions are
   idempotent. Scan tasks and external side effects are excluded: re-running a scan is
   not safe to do automatically, Jira sends would create duplicate issues, the S3
   upload rebuilds from worker-local files that do not survive a crash, and
   report/Security Hub recovery is out of scope.

3. **Recovery cap.** A per-task Valkey counter limits how often the same task is
   re-enqueued. After `--max-attempts` recoveries (default 3) the orphan is marked
   terminal instead of re-enqueued, so a task that repeatedly kills its worker cannot
   loop forever.

A Postgres advisory lock ensures that, even with multiple API/worker replicas, only
one reconciliation runs at a time; the others no-op.

## On-demand command

The same logic is available as a management command, useful right after a deploy or
for manual intervention:

```bash
python manage.py reconcile_orphan_tasks            # recover now
python manage.py reconcile_orphan_tasks --dry-run  # report orphans, change nothing
python manage.py reconcile_orphan_tasks --grace-minutes 5 --max-attempts 3
```

## Configuration

All settings have safe defaults; override via environment variables.

| Env var | Default | Purpose |
| --- | --- | --- |
| `DJANGO_CELERY_WORKER_PREFETCH_MULTIPLIER` | `1` | Tasks reserved per worker process. |
| `DJANGO_CELERY_WORKER_SOFT_SHUTDOWN_TIMEOUT` | `60` | Seconds the worker drains/re-queues on `SIGTERM` before force-kill. |
| `DJANGO_CELERY_TASK_TIME_LIMIT` | `21600` (6h) | Hard limit for most tasks; connection checks are capped at 120s. |
| `DJANGO_CELERY_TASK_SOFT_TIME_LIMIT` | hard - 600 | Soft limit; raises `SoftTimeLimitExceeded` for cleanup. |
| `DJANGO_CELERY_LONG_TASK_TIME_LIMIT` | `172800` (48h) | Hard limit for scans and provider/tenant deletions, which can legitimately run for more than a day. |
| `DJANGO_CELERY_LONG_TASK_SOFT_TIME_LIMIT` | long hard - 600 | Soft limit for the long-running tasks above. |
| `DJANGO_TASK_RECOVERY_ENABLED` | `false` | Master switch for orphan-task recovery, disabled by default (opt-in); set to `true` to enable. When off, no orphan is detected, marked terminal, or re-enqueued (attack-paths stale cleanup still runs). |
| `DJANGO_TASK_RECOVERY_SUMMARIES_ENABLED` | `true` | Auto re-enqueue orphaned scan summary/aggregation tasks. |
| `DJANGO_TASK_RECOVERY_DELETIONS_ENABLED` | `true` | Auto re-enqueue orphaned provider/tenant deletion tasks. |

Recovery is opt-in: with the master flag off (the default) the sweep does nothing.
Once enabled, the per-group flags default to on, so every group recovers unless you
turn one off; a task whose group flag is off is marked terminal instead of
re-enqueued.

Turning recovery off only disables this watchdog sweep; it does not change Celery's
broker-level redelivery (`task_acks_late`/`task_reject_on_worker_lost`), which still
re-delivers tasks that keep `acks_late=True` on worker loss, independently of this flag.

`task_acks_late` and `task_reject_on_worker_lost` are enabled in `config/celery.py`.

## Deployment requirement

Two conditions must both hold for the soft shutdown to actually drain work:

1. **The worker must receive `SIGTERM`.** The container entrypoint `exec`s the
   Celery process so it runs as PID 1; otherwise `SIGTERM` from `docker stop`/ECS
   hits the entrypoint shell, never reaches Celery, and the worker is hard-killed
   (SIGKILL) at the grace deadline without draining. Custom entrypoints must
   preserve the `exec`.
2. **The orchestrator must give the worker enough time** before force-killing it.
   Set the stop grace period to exceed `DJANGO_CELERY_WORKER_SOFT_SHUTDOWN_TIMEOUT`
   plus a margin:
   - **docker-compose:** `stop_grace_period` on the worker services (set to `120s`).
   - **AWS ECS:** the worker container `stopTimeout` (configured in the deployment
     repository).

If either condition is missing, long tasks are still recovered by the watchdog,
but they are cut mid-run on every deploy instead of draining.
