#!/usr/bin/env bash
set -u

# Cross-platform /dev/shm hardening verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Read-only: this script does not modify the system.

FSTAB="/etc/fstab"
SHM="/dev/shm"

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

echo "============================================"
echo " DBalance Cross-Platform /dev/shm Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "============================================"
echo

echo "--- /etc/fstab ---"

FSTAB_LINE="$(
    awk '
        /^[[:space:]]*#/ { next }
        NF >= 4 && $2 == "/dev/shm" { print; exit }
    ' "${FSTAB}" 2>/dev/null
)"

if [[ -n "${FSTAB_LINE}" ]]; then
    pass "/dev/shm entry exists in fstab"
else
    fail "/dev/shm entry missing from fstab"
fi

FSTAB_SRC="$(awk '{print $1}' <<< "${FSTAB_LINE}")"
FSTAB_TYPE="$(awk '{print $3}' <<< "${FSTAB_LINE}")"
FSTAB_OPTIONS="$(awk '{print $4}' <<< "${FSTAB_LINE}")"

[[ "${FSTAB_SRC}" == "tmpfs" ]] &&
    pass "fstab source = tmpfs" ||
    fail "fstab source = ${FSTAB_SRC:-UNKNOWN}"

[[ "${FSTAB_TYPE}" == "tmpfs" ]] &&
    pass "fstab filesystem = tmpfs" ||
    fail "fstab filesystem = ${FSTAB_TYPE:-UNKNOWN}"

for option in nodev nosuid noexec; do
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

if mountpoint -q "${SHM}"; then
    pass "/dev/shm is mounted"
else
    fail "/dev/shm is not mounted"
fi

FSTYPE="$(findmnt -n -o FSTYPE "${SHM}" 2>/dev/null || true)"
OPTIONS="$(findmnt -n -o OPTIONS "${SHM}" 2>/dev/null || true)"

[[ "${FSTYPE}" == "tmpfs" ]] &&
    pass "/dev/shm filesystem = tmpfs" ||
    fail "/dev/shm filesystem = ${FSTYPE:-UNKNOWN}"

echo
echo "--- Runtime Security Options ---"

for option in nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${OPTIONS//,/ }"; then
        pass "/dev/shm has ${option}"
    else
        fail "/dev/shm missing ${option}"
    fi
done

echo
echo "--- Ownership & Permission ---"

OWNER="$(stat -c '%U:%G' "${SHM}" 2>/dev/null || true)"
MODE="$(stat -c '%a' "${SHM}" 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "/dev/shm owner = root:root" ||
    fail "/dev/shm owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "1777" ]] &&
    pass "/dev/shm permission = 1777" ||
    fail "/dev/shm permission = ${MODE:-UNKNOWN}"

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
