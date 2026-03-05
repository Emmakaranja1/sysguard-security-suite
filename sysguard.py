import logging
import os
import sys


SERVICE_PORTS = {
    22: "ssh",
    80: "http",
    443: "https",
    3000: "dev-server",
    9090: "prometheus",
}


HIGH_RISK_PORTS = {22, 3306, 5432, 6379, 27017} 


SCAN_PORTS = "22,80,443,3000,9090"

LOG_FILE = "logs/sysguard.log"


def setup_logging(log_file: str = LOG_FILE) -> logging.Logger:
  
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("sysguard")
    logger.setLevel(logging.INFO)

    
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger