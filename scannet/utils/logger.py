import logging
import sys
from rich.logging import RichHandler

_logger = None

def setup_logger(debug: bool = False) -> logging.Logger:
    global _logger
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Configure logging using rich handler
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    
    _logger = logging.getLogger("netscan")
    _logger.setLevel(log_level)
    return _logger

def get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        return setup_logger()
    return _logger
