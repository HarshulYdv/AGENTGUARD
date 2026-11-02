"""Centralized logging configuration for AGENTGUARD."""

import json
import logging
import sys
from typing import Optional
from backend.core.config import Settings, get_settings


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for production or machine-parsed log ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_payload)


def setup_logging(settings: Optional[Settings] = None) -> None:
    """Initialize root and application loggers according to project settings."""
    if settings is None:
        settings = get_settings()

    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Configure handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    if settings.log_format.lower() == "json":
        formatter: logging.Formatter = JSONFormatter()
    else:
        log_format = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s"
        formatter = logging.Formatter(fmt=log_format, datefmt="%Y-%m-%d %H:%M:%S")

    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing stream handlers to prevent duplicate lines on reload
    for existing_handler in list(root_logger.handlers):
        if isinstance(existing_handler, logging.StreamHandler):
            root_logger.removeHandler(existing_handler)

    root_logger.addHandler(handler)

    # Configure AGENTGUARD parent logger
    app_logger = logging.getLogger("agentguard")
    app_logger.setLevel(log_level)

    # Suppress excessive chatter from third-party libraries if desired
    logging.getLogger("uvicorn.access").setLevel(log_level)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.debug else logging.WARNING
    )


def get_logger(name: str) -> logging.Logger:
    """Convenience helper to obtain namespaced AGENTGUARD loggers."""
    if not name.startswith("agentguard"):
        return logging.getLogger(f"agentguard.{name}")
    return logging.getLogger(name)

