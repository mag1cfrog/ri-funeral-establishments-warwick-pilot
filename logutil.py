import logging, os, sys

def setup_logger(name: str, level: str | None = None) -> logging.Logger:
    lvl = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # idempotent
    logger.setLevel(getattr(logging, lvl, logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    h.setFormatter(fmt)
    logger.addHandler(h)
    # quiet down chatty libs unless you want deep detail
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return logger