import json
import logging
import os
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

try:
    import nmap
except ImportError:
    nmap = None

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server
except ImportError:
    Counter = Gauge = Histogram = start_http_server = None


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
DOCKER_SUBNET = "172.17.0.0/24"
LOCALHOST = "127.0.0.1"


@dataclass
class ScanResult:
    """Structured result container for scan metadata."""

    target: str
    open_ports: list[int]
    open_ports_per_service: dict[str, int]
    high_risk_ports: list[int]
    duration_seconds: float
    timestamp: str
    scan_success: bool
    error_message: Optional[str] = None


def _init_metrics():
    """Initialize Prometheus metrics if prometheus_client is available."""
    if start_http_server is None:
        return None

    metrics = {
        "open_ports_total": Gauge(
            "sysguard_open_ports_total",
            "Total number of open ports detected across all targets",
            ["target"],
        ),
        "high_risk_ports": Gauge(
            "sysguard_high_risk_ports",
            "Number of high-risk ports detected (SSH, DB, etc.)",
            ["target"],
        ),
        "scan_duration_seconds": Histogram(
            "sysguard_scan_duration_seconds",
            "Time taken to complete security scan in seconds",
            ["target"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
        ),
        "scans_total": Counter(
            "sysguard_scans_total",
            "Total number of scans executed",
            ["target", "status"],
        ),
        "open_ports_per_service": Gauge(
            "sysguard_open_ports_per_service",
            "Open ports count per service type",
            ["target", "service"],
        ),
        "vulnerability_simulations": Gauge(
            "sysguard_vulnerability_simulations",
            "Simulated vulnerability check results (1=detected, 0=clean)",
            ["service", "check_type", "severity"],
        ),
        "cpu_percent": Gauge("sysguard_cpu_percent", "System CPU usage percentage"),
        "memory_percent": Gauge(
            "sysguard_memory_percent", "System memory usage percentage"
        ),
    }
    return metrics


# Global metrics object - populated after imports
METRICS = _init_metrics()


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


logger = setup_logging()


class PortScanner:
    """
    Lightweight port scanner for localhost and Docker internal network.
    Uses nmap with minimal privileges - designed for internal use only.
    """

    def __init__(self, ports: str = SCAN_PORTS):
        self.ports = ports
        self._nm = None
        if nmap is None:
            logger.warning(
                "python-nmap not installed. Using fallback socket-based scan. "
                "Install with: pip install python-nmap"
            )

    def _get_nmap(self):
        """Lazy-load nmap to handle optional dependency."""
        if nmap is not None and self._nm is None:
            self._nm = nmap.PortScanner()
        return self._nm

    def scan_target(self, target: str) -> ScanResult:
        """
        Perform a port scan on a single target.
        Returns ScanResult with open ports and metadata.
        """
        start = datetime.now()
        open_ports: list[int] = []
        open_ports_per_service: dict[str, int] = {}
        high_risk: list[int] = []
        success = False
        err_msg = None

        try:
            nm = self._get_nmap()
            if nm is not None:
                # Use -sT for TCP connect scan (works without root)
                # -T4 for reasonable speed, -Pn to skip host discovery
                nm.scan(hosts=target, arguments=f"-p {self.ports} -sT -T4 -Pn")
                if target in nm.all_hosts():
                    for proto in nm[target].all_protocols():
                        for port_num in nm[target][proto].keys():
                            if nm[target][proto][port_num]["state"] == "open":
                                open_ports.append(port_num)
                    success = True
            else:
                # Fallback: simple socket connect for demo without nmap
                for port_str in self.ports.split(","):
                    port = int(port_str.strip())
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1)
                            if s.connect_ex((target, port)) == 0:
                                open_ports.append(port)
                    except (socket.error, socket.timeout, OSError):
                        pass
                success = True

            # Build per-service counts
            for p in open_ports:
                svc = SERVICE_PORTS.get(p, f"port-{p}")
                open_ports_per_service[svc] = open_ports_per_service.get(svc, 0) + 1

            # Identify high-risk ports
            high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]

        except Exception as e:
            err_msg = str(e)
            logger.exception("Scan failed for %s: %s", target, e)

        elapsed = (datetime.now() - start).total_seconds()

        result = ScanResult(
            target=target,
            open_ports=open_ports,
            open_ports_per_service=open_ports_per_service,
            high_risk_ports=high_risk,
            duration_seconds=elapsed,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            scan_success=success,
            error_message=err_msg,
        )

        # Update Prometheus metrics
        if METRICS:
            METRICS["open_ports_total"].labels(target=target).set(len(open_ports))
            METRICS["high_risk_ports"].labels(target=target).set(len(high_risk))
            METRICS["scan_duration_seconds"].labels(target=target).observe(elapsed)
            status = "success" if success else "failure"
            METRICS["scans_total"].labels(target=target, status=status).inc()
            for svc, count in open_ports_per_service.items():
                METRICS["open_ports_per_service"].labels(
                    target=target, service=svc
                ).set(count)

        return result