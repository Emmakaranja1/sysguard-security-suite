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

try:
    import psutil
except ImportError:
    psutil = None


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


@dataclass
class VulnerabilitySimulation:
    """Simulated vulnerability check result for demo/learning purposes."""

    service: str
    check_type: str
    severity: str  # low, medium, high
    detected: bool
    description: str


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


def simulate_vulnerability_checks(
    open_ports: list[int], seed: Optional[int] = None
) -> list[VulnerabilitySimulation]:
    """
    Simulate vulnerability check results using random for demo purposes.
    In production, integrate with tools like OpenVAS, Trivy, or custom checks.
    """
    import random
    
    if seed is not None:
        random.seed(seed)

    results: list[VulnerabilitySimulation] = []
    checks = [
        ("weak_auth", "Authentication misconfiguration", ["low", "medium", "high"]),
        ("default_creds", "Default credentials possible", ["medium", "high"]),
        ("missing_tls", "TLS not enforced", ["high"]),
        ("debug_mode", "Debug mode enabled", ["low", "medium"]),
        ("info_disclosure", "Information disclosure", ["low", "medium"]),
    ]

    for port in open_ports:
        service = SERVICE_PORTS.get(port, f"port-{port}")
        # Simulate: ~20% chance of "finding" a simulated issue
        for check_type, desc, severities in checks:
            detected = random.random() < 0.2
            severity = random.choice(severities)
            results.append(
                VulnerabilitySimulation(
                    service=service,
                    check_type=check_type,
                    severity=severity,
                    detected=detected,
                    description=desc,
                )
            )
            if METRICS and detected:
                METRICS["vulnerability_simulations"].labels(
                    service=service, check_type=check_type, severity=severity
                ).set(1)

    return results


def collect_system_health() -> dict:
    """Collect CPU and memory metrics for observability dashboard."""
    if psutil is None:
        return {"cpu_percent": 0, "memory_percent": 0}

    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent

    if METRICS:
        METRICS["cpu_percent"].set(cpu)
        METRICS["memory_percent"].set(mem)

    return {"cpu_percent": cpu, "memory_percent": mem}


def simulate_alert(
    level: str, message: str, channel: str = "slack"
) -> None:
    """
    Simulate alert to Slack/Discord. In production, use webhooks or SDK.
    For demo: prints formatted message.
    """
    alert_payload = {
        "channel": channel,
        "level": level,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    # Simulated - just log/print
    msg = f"[ALERT {level.upper()}] {channel}: {message}"
    logger.warning("Simulated alert: %s", msg)
    print(f"\n--- Simulated {channel.upper()} Alert ---")
    print(json.dumps(alert_payload, indent=2))
    print("--- End Alert ---\n")


def run_scan(
    targets: Optional[list[str]] = None,
    include_docker: bool = True,
    run_vuln_sim: bool = True,
    run_system_health: bool = True,
) -> list[ScanResult]:
    """
    Run full scan: localhost + optional Docker subnet.
    Returns list of ScanResult for each target.
    """
    if targets is None:
        targets = [LOCALHOST]
        if include_docker:
            # Scan Docker gateway - represents host from container perspective
            targets.append("172.17.0.1")

    scanner = PortScanner()
    results: list[ScanResult] = []

    for target in targets:
        logger.info("Scanning target: %s", target)
        res = scanner.scan_target(target)
        results.append(res)

        # Log structured result for sysguard.log
        log_entry = {
            "event": "scan_complete",
            "target": res.target,
            "open_ports": res.open_ports,
            "open_ports_per_service": res.open_ports_per_service,
            "high_risk_ports": res.high_risk_ports,
            "duration_seconds": round(res.duration_seconds, 3),
            "timestamp": res.timestamp,
            "success": res.scan_success,
        }
        logger.info("Scan result: %s", json.dumps(log_entry))

        if res.high_risk_ports and len(res.high_risk_ports) > 0:
            simulate_alert(
                "warning",
                f"High-risk ports detected on {res.target}: {res.high_risk_ports}",
                "slack",
            )

        if run_vuln_sim and res.open_ports:
            vulns = simulate_vulnerability_checks(res.open_ports)
            detected = [v for v in vulns if v.detected]
            if detected:
                for v in detected:
                    logger.info(
                        "Simulated vuln: %s | %s | %s | %s",
                        v.service,
                        v.check_type,
                        v.severity,
                        v.description,
                    )
                simulate_alert(
                    "info",
                    f"Simulated vuln checks: {len(detected)} items on {res.target}",
                    "discord",
                )

    if run_system_health:
        health = collect_system_health()
        logger.info("System health: %s", json.dumps(health))

    return results


def main():
    """Main entry: start Prometheus HTTP server, run scan, keep server alive."""
    import argparse

    parser = argparse.ArgumentParser(description="SysGuard Security Scanner")
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="Disable Prometheus HTTP server",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=9000,
        help="Port for Prometheus metrics (default: 9000)",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=None,
        help="Override scan targets (e.g., 127.0.0.1 172.17.0.1)",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Skip Docker subnet scan",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run single scan and exit (no continuous mode)",
    )
    args = parser.parse_args()

    # Start Prometheus HTTP server for metrics scraping
    if not args.no_metrics and start_http_server:
        try:
            start_http_server(args.metrics_port)
            logger.info("Prometheus metrics server listening on port %d", args.metrics_port)
        except OSError as e:
            logger.warning("Could not start metrics server: %s", e)

    targets = args.targets
    if targets is None:
        targets = [LOCALHOST]
        if not args.no_docker:
            # In container, use host.docker.internal or gateway
            targets.append("172.17.0.1")  # Docker gateway

    run_scan(
        targets=targets,
        include_docker=not args.no_docker,
        run_vuln_sim=True,
        run_system_health=True,
    )

    if args.once:
        logger.info("Single scan complete. Exiting.")
        return

    # Keep running for continuous metrics scraping
    logger.info("SysGuard running. Metrics at :%d/metrics. Ctrl+C to stop.", args.metrics_port)
    try:
        while True:
            import time
            time.sleep(60)
            # Periodic re-scan (optional enhancement)
            run_scan(targets=targets, include_docker=not args.no_docker)
    except KeyboardInterrupt:
        logger.info("Shutdown requested. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()