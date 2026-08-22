"""Logging-Konfiguration: Datei unter 0700-Verzeichnis, Datei selbst 0600."""
from __future__ import annotations

import logging
import os
import stat
from pathlib import Path


def setup_logging(log_path: Path, verbose: bool = False) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(log_path.parent, stat.S_IRWXU)  # 0700

    logger = logging.getLogger("dmarcwatch")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(file_handler)

    # Sicherstellen, dass die Logdatei nur für den Nutzer lesbar ist (0600),
    # auch wenn sie gerade neu angelegt wurde.
    log_path.touch(exist_ok=True)
    os.chmod(log_path, stat.S_IRUSR | stat.S_IWUSR)

    return logger
