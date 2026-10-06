#!/usr/bin/env bash
set -u

# Cross-platform Chrony verification with synchronization grace period.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Read-only: this script does not modify Chrony configuration.
#
# The verifier waits for Chrony to synchronize after a recent restart
# instead of reporting an immediate false FAIL.
#
# Optional environment variables:
#   CHRONY_WAIT_TIMEOUT=120   Maximum wait time in seconds
#   CHRONY_WAIT_INTERVAL=10   Check interval in seconds

NTP_SERVERS=(
    "0.id.pool.ntp.org"
    "1.id.pool.ntp.org"
    "2.id.pool.ntp.org"
    "3.id.pool.ntp.org"
)

WAIT_TIMEOUT="${CHRONY_WAIT_TIMEOUT:-120}"
WAIT_INTERVAL="${CHRONY_WAIT_INTERVAL:-10}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "[INFO] $*"; }
waitmsg() { echo "[WAIT] $*"; }

[[ -r /etc/os-release ]] || {
    echo "[FAIL] /etc/os-release not found"
    exit 1
}

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"

case "${OS_ID}" in
    ubuntu)
        [[ "${OS_VER}" == "22.04" || "${OS_VER}" == "24.04" ]] || {
            echo "[FAIL] Unsupported Ubuntu version: ${OS_VER}"
            exit 1
        }
        FAMILY="debian"
        CHRONY_CONF="/etc/chrony/chrony.conf"
        CHRONY_SERVICE="chrony.service"
        PACKAGE="chrony"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        FAMILY="debian"
        CHRONY_CONF="/etc/chrony/chrony.conf"
        CHRONY_SERVICE="chrony.service"
        PACKAGE="chrony"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        FAMILY="rhel"
        CHRONY_CONF="/etc/chrony.conf"
        CHRONY_SERVICE="chronyd.service"
        PACKAGE="chrony"
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

for cmd in chronyc chronyd systemctl grep awk stat; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "[FAIL] Required command not found: ${cmd}"
        exit 1
    fi
done

echo "============================================"
echo " Cross-Platform Chrony Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "============================================"
echo

echo "--- Package ---"

if [[ "${FAMILY}" == "debian" ]]; then
    if dpkg-query -W -f='${Status}' "${PACKAGE}" 2>/dev/null |
       grep -q "install ok installed"; then
        pass "${PACKAGE} installed"
    else
        fail "${PACKAGE} not installed"
    fi
else
    if rpm -q "${PACKAGE}" >/dev/null 2>&1; then
        pass "${PACKAGE} installed"
    else
        fail "${PACKAGE} not installed"
    fi
fi

echo
echo "--- Service ---"

systemctl is-active --quiet "${CHRONY_SERVICE}" &&
    pass "${CHRONY_SERVICE} active" ||
    fail "${CHRONY_SERVICE} inactive"

if systemctl is-enabled --quiet "${CHRONY_SERVICE}" 2>/dev/null; then
    pass "${CHRONY_SERVICE} enabled"
else
    STATE="$(systemctl is-enabled "${CHRONY_SERVICE}" 2>/dev/null || true)"
    fail "${CHRONY_SERVICE} state = ${STATE:-unknown}"
fi

echo
echo "--- Configuration ---"

if [[ -f "${CHRONY_CONF}" ]]; then
    pass "Chrony configuration exists: ${CHRONY_CONF}"
else
    fail "Chrony configuration missing: ${CHRONY_CONF}"
fi

for server in "${NTP_SERVERS[@]}"; do
    if grep -Eq \
        "^[[:space:]]*server[[:space:]]+${server//./\\.}([[:space:]]|$).*iburst" \
        "${CHRONY_CONF}" 2>/dev/null; then
        pass "Configured server: ${server}"
    else
        fail "Missing server: ${server}"
    fi
done

ACTIVE_TIME_SOURCES="$(
    grep -Ec '^[[:space:]]*(server|pool)[[:space:]]+' "${CHRONY_CONF}" 2>/dev/null || true
)"

if [[ "${ACTIVE_TIME_SOURCES}" == "4" ]]; then
    pass "Exactly 4 active NTP source directives configured"
else
    fail "Active server/pool directives = ${ACTIVE_TIME_SOURCES}; expected 4"
fi

if chronyd -p -f "${CHRONY_CONF}" >/dev/null 2>&1; then
    pass "Chrony configuration syntax valid"
else
    fail "Chrony configuration syntax invalid"
fi

echo
echo "--- Synchronization ---"

# Count all Chrony source rows, regardless of current source state.
SOURCE_COUNT="$(
    chronyc sources -n 2>/dev/null |
    awk '$1 ~ /^[\^\=\#]/ {count++} END {print count+0}'
)"

if [[ "${SOURCE_COUNT}" =~ ^[0-9]+$ ]] && (( SOURCE_COUNT > 0 )); then
    pass "Chrony NTP sources available (${SOURCE_COUNT})"
else
    fail "No Chrony NTP sources available"
fi

# Chrony may need time to collect samples after daemon restart.
# Wait until all core synchronization indicators become healthy.
ELAPSED=0
SYNC_READY=0

while (( ELAPSED <= WAIT_TIMEOUT )); do
    TRACKING="$(chronyc tracking 2>/dev/null || true)"
    SOURCES="$(chronyc sources -n 2>/dev/null || true)"

    LEAP_STATUS="$(
        awk -F: '/Leap status/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            print $2
            exit
        }' <<< "${TRACKING}"
    )"

    STRATUM="$(
        awk -F: '/^Stratum/ {
            gsub(/[[:space:]]/, "", $2)
            print $2
            exit
        }' <<< "${TRACKING}"
    )"

    SELECTED_SOURCE="$(
        awk '$1 == "^*" {print $2; exit}' <<< "${SOURCES}"
    )"

    SYNCED="$(
        timedatectl show \
            --property=NTPSynchronized \
            --value 2>/dev/null || true
    )"

    if [[ "${LEAP_STATUS}" == "Normal" ]] &&
       [[ -n "${SELECTED_SOURCE}" ]] &&
       [[ "${STRATUM}" =~ ^[0-9]+$ ]] &&
       (( STRATUM > 0 && STRATUM < 16 )) &&
       [[ "${SYNCED}" == "yes" ]]; then
        SYNC_READY=1
        break
    fi

    if (( ELAPSED >= WAIT_TIMEOUT )); then
        break
    fi

    waitmsg "Chrony not synchronized yet: leap=${LEAP_STATUS:-UNKNOWN}, selected=${SELECTED_SOURCE:-NONE}, stratum=${STRATUM:-UNKNOWN}, NTPSynchronized=${SYNCED:-UNKNOWN}. Waiting ${WAIT_INTERVAL}s..."
    sleep "${WAIT_INTERVAL}"
    ELAPSED=$((ELAPSED + WAIT_INTERVAL))
done

if (( SYNC_READY == 1 )); then
    pass "Chrony leap status = Normal"
    pass "Selected NTP source = ${SELECTED_SOURCE}"
    pass "Chrony stratum = ${STRATUM}"
    pass "System clock synchronized"
    info "Synchronization became healthy after ${ELAPSED} second(s)."
else
    fail "Chrony leap status = ${LEAP_STATUS:-UNKNOWN}"
    fail "Selected NTP source = ${SELECTED_SOURCE:-NONE}"
    fail "Chrony stratum = ${STRATUM:-UNKNOWN}"
    fail "System clock synchronized = ${SYNCED:-UNKNOWN}"
    info "Synchronization did not become healthy within ${WAIT_TIMEOUT} seconds."
fi

echo
echo "--- Source State ---"

chronyc sources -n 2>/dev/null |
awk '
    $1 ~ /^[\^\=\#][*+\-?x~]/ {
        printf "  %-3s %-40s stratum=%-3s reach=%-4s lastRx=%s\n",
               $1, $2, $3, $5, $6
    }
' || true

echo
echo "--- Conflict Check ---"

if systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
    if ! systemctl is-active --quiet systemd-timesyncd.service 2>/dev/null; then
        pass "systemd-timesyncd inactive"
    else
        fail "systemd-timesyncd still active"
    fi
else
    pass "systemd-timesyncd not installed"
fi

if systemctl list-unit-files ntpd.service >/dev/null 2>&1; then
    if ! systemctl is-active --quiet ntpd.service 2>/dev/null; then
        pass "ntpd inactive"
    else
        fail "ntpd still active"
    fi
else
    pass "ntpd not installed"
fi

echo
echo "--- File Security ---"

OWNER="$(stat -c '%U:%G' "${CHRONY_CONF}" 2>/dev/null || true)"
MODE="$(stat -c '%a' "${CHRONY_CONF}" 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "Chrony config owner = root:root" ||
    fail "Chrony config owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "644" ]] &&
    pass "Chrony config permission = 644" ||
    fail "Chrony config permission = ${MODE:-UNKNOWN}"

echo
echo "============================================"

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "============================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "============================================"
    exit 1
fi
