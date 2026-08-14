"""Logging utilities for CVEye."""

from __future__ import annotations

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)
_logger: Optional[logging.Logger] = None


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Setup logging handler and level."""
    global _logger
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
        force=True,
    )
    _logger = logging.getLogger("cveye")
    _logger.setLevel(level)
    return _logger


def get_logger() -> logging.Logger:
    """Get global logger instance."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger
