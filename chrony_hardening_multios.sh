#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform Chrony hardening using Indonesia NTP Pool.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# - Use Chrony as the time synchronization service
# - Use Indonesia NTP Pool servers
# - Disable systemd-timesyncd if present
# - Keep configuration persistent and idempotent

NTP_SERVERS=(
    "0.id.pool.ntp.org"
    "1.id.pool.ntp.org"
    "2.id.pool.ntp.org"
    "3.id.pool.ntp.org"
)

BACKUP_ROOT="/var/backups/chrony-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"

case "${OS_ID}" in
    ubuntu)
        [[ "${OS_VER}" == "22.04" || "${OS_VER}" == "24.04" ]] ||
            fail "Unsupported Ubuntu version: ${OS_VER}"
        FAMILY="debian"
        CHRONY_CONF="/etc/chrony/chrony.conf"
        CHRONY_SERVICE="chrony.service"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] ||
            fail "Unsupported Debian version: ${OS_VER}"
        FAMILY="debian"
        CHRONY_CONF="/etc/chrony/chrony.conf"
        CHRONY_SERVICE="chrony.service"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] ||
            fail "Unsupported RHEL version: ${OS_VER}"
        FAMILY="rhel"
        CHRONY_CONF="/etc/chrony.conf"
        CHRONY_SERVICE="chronyd.service"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        ;;
esac

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying Chrony Configuration ==="

if [[ "${FAMILY}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq chrony
else
    dnf install -y -q chrony
fi

command -v chronyd >/dev/null 2>&1 || fail "chronyd not found."
command -v chronyc >/dev/null 2>&1 || fail "chronyc not found."

[[ -f "${CHRONY_CONF}" ]] ||
    fail "Chrony configuration file not found: ${CHRONY_CONF}"

mkdir -p "${BACKUP_DIR}"
cp -a "${CHRONY_CONF}" "${BACKUP_DIR}/$(basename "${CHRONY_CONF}")"

log "Backup created: ${BACKUP_DIR}"

# Disable systemd-timesyncd when present so Chrony is the only time daemon.
if systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
    systemctl disable --now systemd-timesyncd.service >/dev/null 2>&1 || true
fi

# Stop legacy ntpd if it exists and is active.
if systemctl list-unit-files ntpd.service >/dev/null 2>&1; then
    systemctl disable --now ntpd.service >/dev/null 2>&1 || true
fi

# Remove active pool/server directives while preserving comments and all
# unrelated Chrony settings.
sed -Ei \
    '/^[[:space:]]*(pool|server)[[:space:]]+/d' \
    "${CHRONY_CONF}"

cat >> "${CHRONY_CONF}" <<'EOF'

# DBalance Indonesia NTP Pool
server 0.id.pool.ntp.org iburst
server 1.id.pool.ntp.org iburst
server 2.id.pool.ntp.org iburst
server 3.id.pool.ntp.org iburst
EOF

chown root:root "${CHRONY_CONF}"
chmod 0644 "${CHRONY_CONF}"

# Validate configuration before restart.
chronyd -p -f "${CHRONY_CONF}" >/dev/null 2>&1 ||
    fail "Chrony configuration validation failed."

systemctl enable "${CHRONY_SERVICE}" >/dev/null 2>&1 ||
    fail "Failed to enable ${CHRONY_SERVICE}."

systemctl restart "${CHRONY_SERVICE}" ||
    fail "Failed to restart ${CHRONY_SERVICE}."

systemctl is-active --quiet "${CHRONY_SERVICE}" ||
    fail "${CHRONY_SERVICE} is not active."

# Ask Chrony to refresh sources without forcing a clock step.
chronyc online >/dev/null 2>&1 || true
chronyc burst 4/4 >/dev/null 2>&1 || true

log "=== Chrony Configuration Applied Successfully ==="
log "Backup location: ${BACKUP_DIR}"
log "Service: ${CHRONY_SERVICE}"
log "Configuration: ${CHRONY_CONF}"
log "Run /root/chrony_hardening_verifikasi.sh"
