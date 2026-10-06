#!/usr/bin/env bash
set -u

# Cross-platform /var/tmp bind mount verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Read-only: this script does not modify the system.

FSTAB="/etc/fstab"
TMP_DIR="/tmp"
VAR_TMP_DIR="/var/tmp"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

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
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

echo "================================================"
echo " DBalance Cross-Platform /var/tmp Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "================================================"
echo

echo "--- /etc/fstab ---"

FSTAB_LINE="$(
    awk '
        /^[[:space:]]*#/ { next }
        NF >= 4 && $2 == "/var/tmp" { print; exit }
    ' "${FSTAB}" 2>/dev/null
)"

if [[ -n "${FSTAB_LINE}" ]]; then
    pass "/var/tmp entry exists in fstab"
else
    fail "/var/tmp entry missing from fstab"
fi

FSTAB_SOURCE="$(awk '{print $1}' <<< "${FSTAB_LINE}")"
FSTAB_TYPE="$(awk '{print $3}' <<< "${FSTAB_LINE}")"
FSTAB_OPTIONS="$(awk '{print $4}' <<< "${FSTAB_LINE}")"

[[ "${FSTAB_SOURCE}" == "/tmp" ]] &&
    pass "fstab source = /tmp" ||
    fail "fstab source = ${FSTAB_SOURCE:-UNKNOWN}"

[[ "${FSTAB_TYPE}" == "none" ]] &&
    pass "fstab filesystem type = none" ||
    fail "fstab filesystem type = ${FSTAB_TYPE:-UNKNOWN}"

for option in bind rw nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${FSTAB_OPTIONS//,/ }"; then
        pass "fstab contains ${option}"
    else
        fail "fstab missing ${option}"
    fi
done

if findmnt --verify --tab-file "${FSTAB}" >/dev/null 2>&1; then
    pass "/etc/fstab syntax valid"
else
    fail "/etc/fstab syntax invalid"
fi

echo
echo "--- Runtime Mount ---"

if mountpoint -q "${VAR_TMP_DIR}"; then
    pass "/var/tmp is a dedicated mount"
else
    fail "/var/tmp is not mounted"
fi

TMP_ID="$(stat -Lc '%d:%i' "${TMP_DIR}" 2>/dev/null || true)"
VAR_TMP_ID="$(stat -Lc '%d:%i' "${VAR_TMP_DIR}" 2>/dev/null || true)"

if [[ -n "${TMP_ID}" && "${TMP_ID}" == "${VAR_TMP_ID}" ]]; then
    pass "/var/tmp is bind-mounted from /tmp"
else
    fail "/var/tmp is not the same bind-mounted directory as /tmp"
fi

TMP_FSTYPE="$(findmnt -n -o FSTYPE "${TMP_DIR}" 2>/dev/null || true)"
VAR_TMP_FSTYPE="$(findmnt -n -o FSTYPE "${VAR_TMP_DIR}" 2>/dev/null || true)"

if [[ -n "${TMP_FSTYPE}" && "${TMP_FSTYPE}" == "${VAR_TMP_FSTYPE}" ]]; then
    pass "/var/tmp filesystem matches /tmp (${VAR_TMP_FSTYPE})"
else
    fail "/tmp filesystem=${TMP_FSTYPE:-UNKNOWN}, /var/tmp filesystem=${VAR_TMP_FSTYPE:-UNKNOWN}"
fi

echo
echo "--- Runtime Security Options ---"

OPTIONS="$(findmnt -n -o OPTIONS "${VAR_TMP_DIR}" 2>/dev/null || true)"

for option in nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${OPTIONS//,/ }"; then
        pass "/var/tmp has ${option}"
    else
        fail "/var/tmp missing ${option}"
    fi
done

echo
echo "--- Ownership & Permission ---"

OWNER="$(stat -c '%U:%G' "${VAR_TMP_DIR}" 2>/dev/null || true)"
MODE="$(stat -c '%a' "${VAR_TMP_DIR}" 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "/var/tmp owner = root:root" ||
    fail "/var/tmp owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "1777" ]] &&
    pass "/var/tmp permission = 1777" ||
    fail "/var/tmp permission = ${MODE:-UNKNOWN}"

echo
echo "--- /tmp Relationship ---"

TMP_OPTIONS="$(findmnt -n -o OPTIONS "${TMP_DIR}" 2>/dev/null || true)"

for option in nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${TMP_OPTIONS//,/ }"; then
        pass "/tmp has ${option}"
    else
        fail "/tmp missing ${option}; source hardening should be reviewed"
    fi
done

echo
echo "================================================"

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "================================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "================================================"
    exit 1
fi
