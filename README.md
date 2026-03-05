# SysGuard

**Security Automation for Data Centre Operations**

Enterprise vulnerability scanners (Nessus, OpenVAS, etc.) are often overkill for internal lab environments and containerised workloads. SysGuard addresses that gap: a lightweight security scanner built for localhost and internal Docker networks, designed to integrate directly with existing Prometheus/Grafana observability stacks. Run periodic port scans, surface findings as metrics, and keep an audit trail—without spinning up heavyweight tooling.



## Features

- **Port scanning** – Lightweight scans of ports 22, 80, 443, 3000, 9090 via `python-nmap`
- **Safe targets only** – localhost and Docker gateway; no external scanning
- **Prometheus metrics** – Exposed on port 9000 for dashboards and alerting
- **Structured logging** – JSON-style entries to `logs/sysguard.log` for audit and SIEM
- **Extensible checks** – Framework for custom misconfiguration detection (plug in real scanners as needed)
- **System health** – CPU and memory metrics alongside security data
- **Alert pipeline** – Output format ready for Slack, Discord, or PagerDuty webhooks



## Architecture


flowchart LR
    subgraph targets["Scan Targets"]
        localhost["127.0.0.1"]
        docker["172.17.0.1"]
    end

    subgraph sysguard["SysGuard Container"]
        scanner["Port Scanner\npython-nmap"]
        metrics["Metrics API\n:9000/metrics"]
        scanner --> metrics
    end

    subgraph observability["Observability Stack"]
        prometheus["Prometheus\n:9090"]
        grafana["Grafana\n:3000"]
    end

    localhost --> scanner
    docker --> scanner
    metrics -->|scrape| prometheus
    prometheus -->|datasource| grafana

    scanner -.->|stdout + file| logs["logs/sysguard.log"]

```
<details>
<summary>Text diagram (fallback)</summary>


  localhost ──┐                    scrape
  172.17.0.1 ─┼──► SysGuard ──────────────► Prometheus ──► Grafana
              │    (port scan)   :9000         :9090         :3000
              └──► logs/sysguard.log

</details>
```


## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.9+ (for local runs)
- `nmap` installed (for port scanning)

### Run with Docker Compose (Recommended)

```bash
# Build and start all services
# Use "docker compose" (v2) or "docker-compose" (v1)
docker compose up -d

# View logs
docker compose logs -f sysguard

# Access
# - SysGuard metrics:  http://localhost:9000/metrics
# - Prometheus:        http://localhost:9090
# - Grafana:           http://localhost:3000 (admin/admin)
```

### Run Locally (Python)

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install nmap (required for scanning)
# Ubuntu/Debian: sudo apt install nmap
# macOS: brew install nmap

# Run SysGuard (metrics server + scan)
python sysguard.py

# Single scan then exit
python sysguard.py --once
```

### Run via Bash Script

```bash
chmod +x run_sysguard_scan.sh

# Default: run scan, log to logs/sysguard.log
./run_sysguard_scan.sh

# Simulate alerts
./run_sysguard_scan.sh --alert

# Run scan inside Docker
./run_sysguard_scan.sh --docker


```
## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sysguard_open_ports_total` | Gauge | Total open ports per target |
| `sysguard_high_risk_ports` | Gauge | High-risk ports (SSH, DB, etc.) per target |
| `sysguard_scan_duration_seconds` | Histogram | Scan duration in seconds |
| `sysguard_scans_total` | Counter | Total scans (success/failure) |
| `sysguard_open_ports_per_service` | Gauge | Open ports per service (ssh, http, etc.) |
| `sysguard_vulnerability_simulations` | Gauge | Simulated vuln check results |
| `sysguard_cpu_percent` | Gauge | System CPU usage |
| `sysguard_memory_percent` | Gauge | System memory usage |

### Example Metrics Output

```
# HELP sysguard_open_ports_total Total number of open ports detected across all targets
# TYPE sysguard_open_ports_total gauge
sysguard_open_ports_total{target="127.0.0.1"} 3.0
sysguard_open_ports_total{target="172.17.0.1"} 2.0

# HELP sysguard_scan_duration_seconds Time taken to complete security scan in seconds
# TYPE sysguard_scan_duration_seconds histogram
sysguard_scan_duration_seconds_bucket{target="127.0.0.1",le="1.0"} 1.0
```

---



## Grafana Setup

1. Open http://localhost:3000 and log in with `admin` / `admin`
2. Prometheus is pre-configured as the default datasource
3. Create a new dashboard and add panels using the SysGuard metrics above

**Sample PromQL queries:**

- Total open ports: `sysguard_open_ports_total`
- High-risk ports: `sysguard_high_risk_ports`
- Scan duration (p95): `histogram_quantile(0.95, sysguard_scan_duration_seconds_bucket)`



## Project Structure

```
SysGuard/
├── sysguard.py           # Main Python security tool
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container image (non-root, minimal)
├── docker-compose.yml    # SysGuard + Prometheus + Grafana
├── prometheus.yml        # Prometheus scrape config
├── run_sysguard_scan.sh  # Bash automation script
├── grafana/
│   └── provisioning/
│       └── datasources/
│           └── datasources.yml
├── logs/
│   └── sysguard.log      # Structured scan logs
└── README.md
```

## Command-Line Options

```
python sysguard.py [OPTIONS]

  --no-metrics     Disable Prometheus HTTP server
  --metrics-port   Port for metrics (default: 9000)
  --targets        Override scan targets (e.g., 127.0.0.1 172.17.0.1)
  --no-docker      Skip Docker subnet scan
  --once           Run single scan and exit
```


## Safety & Ethics

- **Internal use only** – Scans localhost and Docker gateway (172.17.0.0/24)
- **No external targets** – Never scan IPs outside your control
- **Lightweight** – Limited port set, reasonable timeouts
- **Non-root container** – Runs as unprivileged `sysguard` user



## Technical Overview

| Component | Implementation |
|-----------|----------------|
| **Scanner** | Modular `PortScanner` class, nmap with socket fallback |
| **Metrics** | Prometheus gauges/histograms, scrape-ready on :9000 |
| **Logging** | Dual output (stdout + file) for container logs and audit trail |
| **Container** | Multi-stage Dockerfile, non-root user, health check |
| **Stack** | Prometheus + Grafana with datasource provisioning |
| **Automation** | Bash wrapper for cron/scheduled runs |



## License

MIT