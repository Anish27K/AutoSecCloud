import logging
from pathlib import Path

from pythonjsonlogger import jsonlogger


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_DIRECTORY = PROJECT_ROOT / "logs"

LOG_DIRECTORY.mkdir(
    parents=True,
    exist_ok=True
)

LOG_FILE = LOG_DIRECTORY / "security_logs.log"


# ==========================================
# LOGGER CONFIGURATION
# ==========================================

logger = logging.getLogger("autosec_logger")

logger.setLevel(logging.INFO)

logger.propagate = False


# ==========================================
# FILE HANDLER
# ==========================================

if not any(
    getattr(handler, "baseFilename", None)
    == str(LOG_FILE.resolve())
    for handler in logger.handlers
):

    log_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(message)s"
    )

    log_handler.setFormatter(formatter)

    logger.addHandler(log_handler)