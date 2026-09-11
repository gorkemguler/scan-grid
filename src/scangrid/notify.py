"""Pluggable notification sinks with a severity floor."""

from __future__ import annotations

import logging

import httpx

from .config import Settings, get_settings

log = logging.getLogger("scangrid.notify")

_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Notifier:
    def __init__(self, settings: Settings | None = None) -> None:
        self.s = settings or get_settings()

    def _below_floor(self, severity: str) -> bool:
        return _ORDER.get(severity, 2) < _ORDER.get(self.s.notify_min_severity, 2)

    def send(self, title: str, body: str = "", severity: str = "medium") -> bool:
        if self._below_floor(severity):
            return True
        backend = self.s.notify_backend
        try:
            if backend == "none":
                return True
            if backend == "log":
                log.warning("NOTIFY [%s] %s - %s", severity, title, body)
                return True
            if backend == "ntfy":
                return self._ntfy(title, body, severity)
            if backend == "telegram":
                return self._telegram(title, body, severity)
            if backend == "webhook":
                return self._webhook(title, body, severity)
        except Exception as exc:  # pragma: no cover - network dependent
            log.error("notify via %s failed: %s", backend, exc)
        return False

    def _ntfy(self, title: str, body: str, severity: str) -> bool:
        if not self.s.ntfy_topic:
            log.error("ntfy selected but SCANGRID_NTFY_TOPIC empty")
            return False
        prio = {
            "info": "min",
            "low": "low",
            "medium": "default",
            "high": "high",
            "critical": "urgent",
        }
        r = httpx.post(
            f"{self.s.ntfy_url.rstrip('/')}/{self.s.ntfy_topic}",
            content=body or title,
            headers={"Title": title, "Priority": prio.get(severity, "default"), "Tags": "scangrid"},
            timeout=10,
        )
        return r.is_success

    def _telegram(self, title: str, body: str, severity: str) -> bool:
        if not (self.s.telegram_bot_token and self.s.telegram_chat_id):
            return False
        text = f"*{title}*\n{body}".strip()
        r = httpx.post(
            f"https://api.telegram.org/bot{self.s.telegram_bot_token}/sendMessage",
            json={"chat_id": self.s.telegram_chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
        return r.is_success

    def _webhook(self, title: str, body: str, severity: str) -> bool:
        if not self.s.webhook_url:
            return False
        r = httpx.post(
            self.s.webhook_url,
            json={"title": title, "body": body, "severity": severity, "source": "scan-grid"},
            timeout=10,
        )
        return r.is_success
