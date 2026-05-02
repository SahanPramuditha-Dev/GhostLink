import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        return json.dumps(log_entry)

def setup_json_logger(filename: str = "ghostlink_attack.json") -> logging.Logger:
    """Create a logger that writes JSON lines to a file."""
    logger = logging.getLogger("ghostlink.json")
    handler = logging.FileHandler(filename)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger