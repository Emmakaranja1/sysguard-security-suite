set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/sysguard.log"
ALERT_SIMULATE=false
USE_DOCKER=false

for arg in "$@"; do
    case $arg in
        --alert)
            ALERT_SIMULATE=true
            ;;
        --docker)
            USE_DOCKER=true
            ;;
        -h|--help)
            echo "SysGuard Run Scan Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --alert    Simulate alert output (Slack/Discord style)"
            echo "  --docker   Run scan inside Docker container"
            echo "  -h, --help Show this help"
            exit 0
            ;;
    esac
done


mkdir -p "$LOG_DIR"

log_message() {
    local level="$1"
    local msg="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}


simulate_alert() {
    if [ "$ALERT_SIMULATE" = true ]; then
        local level="$1"
        local message="$2"
        log_message "ALERT" "Simulated $level: $message"
        echo "--- Simulated Slack/Discord Alert ---"
        echo "{\"level\":\"$level\",\"message\":\"$message\",\"timestamp\":\"$(date -Iseconds)\"}"
        echo "--- End Alert ---"
    fi
}


run_scan() {
    log_message "INFO" "Starting SysGuard security scan..."

    if [ "$USE_DOCKER" = true ]; then
        log_message "INFO" "Running scan via Docker..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm sysguard \
            python sysguard.py --once --no-docker 2>&1 | tee -a "$LOG_FILE"
    else
    
        if command -v python3 &>/dev/null; then
            cd "$SCRIPT_DIR"
            python3 sysguard.py --once 2>&1 | tee -a "$LOG_FILE"
        else
            log_message "ERROR" "python3 not found. Install Python or use --docker"
            exit 1
        fi
    fi

    local exit_code=${PIPESTATUS[0]}
    log_message "INFO" "Scan completed with exit code: $exit_code"

    
    if grep -q "high_risk_ports" "$LOG_FILE" 2>/dev/null; then
        simulate_alert "warning" "High-risk ports may have been detected. Review $LOG_FILE"
    fi

    return $exit_code
}


log_message "INFO" "=========================================="
log_message "INFO" "SysGuard Scan Started"
log_message "INFO" "=========================================="

run_scan
EXIT=$?

log_message "INFO" "SysGuard Scan Finished"
log_message "INFO" "Results logged to: $LOG_FILE"

exit $EXIT
