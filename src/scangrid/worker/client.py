"""HTTP client the worker uses against the orchestrator."""

from __future__ import annotations

import logging

import httpx

from ..config import Settings, get_settings
from ..schemas import ClaimRequest, ClaimResponse, JobResult

log = logging.getLogger("scangrid.worker.client")


class OrchestratorClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.s = settings or get_settings()
        self._c = httpx.Client(
            base_url=self.s.orchestrator_url.rstrip("/"),
            headers={"Authorization": f"Bearer {self.s.api_token}"},
            timeout=30,
        )

    def healthy(self) -> bool:
        try:
            return self._c.get("/healthz").is_success
        except httpx.HTTPError:
            return False

    def claim(self) -> ClaimResponse:
        r = self._c.post(
            "/api/worker/claim",
            json=ClaimRequest(worker_id=self.s.worker_id).model_dump(),
        )
        r.raise_for_status()
        return ClaimResponse.model_validate(r.json())

    def mark_running(self, job_id: int) -> None:
        try:
            self._c.post(f"/api/worker/jobs/{job_id}/running")
        except httpx.HTTPError as exc:  # non-fatal
            log.debug("mark_running failed: %s", exc)

    def submit(self, result: JobResult) -> bool:
        try:
            r = self._c.post(
                f"/api/worker/jobs/{result.job_id}/result",
                json=result.model_dump(mode="json"),
            )
            r.raise_for_status()
            log.info("job %s result accepted: %s", result.job_id, r.json())
            return True
        except httpx.HTTPError as exc:
            log.error("submitting job %s failed: %s", result.job_id, exc)
            return False

    def close(self) -> None:
        self._c.close()
