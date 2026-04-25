"""
GHOSTLINK JSON Logger
=====================
Structured JSON session logging.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Serialize log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def setup_json_logger(log_path: Path | None = None) -> logging.Logger:
    """Create or return the application JSON logger."""
    logger = logging.getLogger("ghostlink.json")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    target_path = log_path or Path("logs") / "ghostlink.jsonl"
    target_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(target_path, encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

    return logger
