"""Worker loop: poll -> claim -> allowlist re-check -> nmap -> submit."""

from __future__ import annotations

import logging
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from ..allowlist import AllowlistError, assert_hosts_allowed, reload_cache
from ..config import get_settings
from ..nmap_runner import run as run_nmap
from ..schemas import JobResult, JobSpec
from .client import OrchestratorClient

log = logging.getLogger("scangrid.worker")


class Worker:
    def __init__(self) -> None:
        self.s = get_settings()
        self.client = OrchestratorClient(self.s)
        self.pool = ThreadPoolExecutor(max_workers=max(1, self.s.worker_concurrency))
        self._stop = False
        self._inflight = 0

    def _execute(self, spec: JobSpec) -> None:
        self._inflight += 1
        try:
            # Belt-and-braces: the orchestrator already checked, we check again
            # on the box that actually runs nmap.
            reload_cache()
            assert_hosts_allowed(spec.hosts)
        except AllowlistError as exc:
            log.error("refusing job %s: %s", spec.job_id, exc)
            self.client.submit(
                JobResult(job_id=spec.job_id, worker_id=self.s.worker_id, ok=False, error=str(exc))
            )
            self._inflight -= 1
            return

        self.client.mark_running(spec.job_id)
        log.info(
            "job %s: scanning %d host(s) for target %s",
            spec.job_id,
            len(spec.hosts),
            spec.target_name,
        )
        try:
            result = run_nmap(spec.hosts, spec.nmap_args, spec.job_id, self.s.worker_id)
        except Exception as exc:  # pragma: no cover - defensive
            result = JobResult(
                job_id=spec.job_id,
                worker_id=self.s.worker_id,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        self.client.submit(result)
        self._inflight -= 1

    def run(self) -> None:
        logging.basicConfig(
            level=self.s.log_level.upper(),
            format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        )
        log.info("worker %s -> %s", self.s.worker_id, self.s.orchestrator_url)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._handle_signal)

        while not self._stop:
            if self._inflight >= self.s.worker_concurrency:
                time.sleep(1)
                continue
            try:
                resp = self.client.claim()
            except Exception as exc:  # network / auth
                log.warning("claim failed: %s", exc)
                time.sleep(self.s.worker_poll_seconds)
                continue

            if resp.job is None:
                time.sleep(self.s.worker_poll_seconds)
                continue
            self.pool.submit(self._execute, resp.job)

        self.pool.shutdown(wait=True)
        self.client.close()

    def _handle_signal(self, *_a) -> None:
        log.info("stopping worker (waiting for in-flight scans)")
        self._stop = True


def main() -> None:
    try:
        Worker().run()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
