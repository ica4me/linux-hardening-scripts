#!/usr/bin/env bash
set -u

# Cross-platform /tmp hardening verification.
# Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x
# Read-only: this script does not change the system.

UNIT="/etc/systemd/system/tmp.mount"

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

echo "==========================================="
echo " DBalance Cross-Platform /tmp Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "==========================================="
echo

echo "--- systemd Unit ---"

if [[ -f "${UNIT}" ]]; then
    pass "tmp.mount unit exists"
else
    fail "tmp.mount unit missing"
fi

if systemctl is-enabled --quiet tmp.mount 2>/dev/null; then
    pass "tmp.mount enabled"
else
    STATE="$(systemctl is-enabled tmp.mount 2>/dev/null || true)"
    fail "tmp.mount state = ${STATE:-unknown}"
fi

if [[ -f "${UNIT}" ]] && systemd-analyze verify "${UNIT}" >/dev/null 2>&1; then
    pass "tmp.mount unit syntax valid"
else
    fail "tmp.mount unit syntax invalid"
fi

if grep -Eq '^What=tmpfs[[:space:]]*$' "${UNIT}" 2>/dev/null &&
   grep -Eq '^Where=/tmp[[:space:]]*$' "${UNIT}" 2>/dev/null &&
   grep -Eq '^Type=tmpfs[[:space:]]*$' "${UNIT}" 2>/dev/null; then
    pass "tmp.mount definition targets /tmp as tmpfs"
else
    fail "tmp.mount definition is incorrect"
fi

UNIT_OPTIONS="$(
    awk -F= '$1=="Options"{print $2; exit}' "${UNIT}" 2>/dev/null
)"

for option in nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${UNIT_OPTIONS//,/ }"; then
        pass "tmp.mount unit contains ${option}"
    else
        fail "tmp.mount unit missing ${option}"
    fi
done

if grep -qw "mode=1777" <<< "${UNIT_OPTIONS//,/ }"; then
    pass "tmp.mount unit contains mode=1777"
else
    fail "tmp.mount unit missing mode=1777"
fi

echo
echo "--- Runtime Mount ---"

if mountpoint -q /tmp; then
    pass "/tmp is a dedicated mount"
else
    fail "/tmp is not a dedicated mount; reboot may be required"
fi

FSTYPE="$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)"
OPTIONS="$(findmnt -n -o OPTIONS /tmp 2>/dev/null || true)"

[[ "${FSTYPE}" == "tmpfs" ]] &&
    pass "/tmp filesystem = tmpfs" ||
    fail "/tmp filesystem = ${FSTYPE:-UNKNOWN}"

echo
echo "--- Runtime Security Options ---"

for option in nodev nosuid noexec; do
    if grep -qw "${option}" <<< "${OPTIONS//,/ }"; then
        pass "/tmp has ${option}"
    else
        fail "/tmp missing ${option}"
    fi
done

echo
echo "--- Ownership & Permission ---"

OWNER="$(stat -c '%U:%G' /tmp 2>/dev/null || true)"
MODE="$(stat -c '%a' /tmp 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "/tmp owner = root:root" ||
    fail "/tmp owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "1777" ]] &&
    pass "/tmp permission = 1777" ||
    fail "/tmp permission = ${MODE:-UNKNOWN}"

echo
echo "--- Unit Runtime State ---"

if systemctl is-active --quiet tmp.mount 2>/dev/null; then
    pass "tmp.mount active"
else
    STATE="$(systemctl is-active tmp.mount 2>/dev/null || true)"
    fail "tmp.mount runtime state = ${STATE:-unknown}; reboot may be required"
fi

echo
echo "==========================================="

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "==========================================="
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "==========================================="
    exit 1
fi
