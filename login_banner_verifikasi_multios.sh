#!/usr/bin/env bash
set -u

# Cross-platform login banner verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Read-only: this script does not modify the system.

ISSUE="/etc/issue"

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

echo "=============================================="
echo " DBalance Cross-Platform Login Banner Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "=============================================="
echo

echo "--- Banner File ---"

REAL_ISSUE="$(readlink -e "${ISSUE}" 2>/dev/null || true)"

if [[ -n "${REAL_ISSUE}" && -f "${REAL_ISSUE}" ]]; then
    pass "/etc/issue exists"
else
    fail "/etc/issue not found"
fi

OWNER="$(stat -Lc '%U:%G' "${ISSUE}" 2>/dev/null || true)"
MODE="$(stat -Lc '%a' "${ISSUE}" 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "/etc/issue owner = root:root" ||
    fail "/etc/issue owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "644" ]] &&
    pass "/etc/issue permission = 644" ||
    fail "/etc/issue permission = ${MODE:-UNKNOWN}; expected 644"

echo
echo "--- Banner Content ---"

grep -Fq "USAGE WARNING" "${ISSUE}" 2>/dev/null &&
    pass "Usage warning present" ||
    fail "Usage warning missing"

grep -Fq "DATACOMM PRIVATE PROPRIETARY" "${ISSUE}" 2>/dev/null &&
    pass "DATACOMM proprietary notice present" ||
    fail "DATACOMM proprietary notice missing"

grep -Fq "consent to monitoring" "${ISSUE}" 2>/dev/null &&
    pass "Monitoring consent notice present" ||
    fail "Monitoring consent notice missing"

grep -Fq "Unauthorized use may subject you to" "${ISSUE}" 2>/dev/null &&
    pass "Unauthorized-use notice present" ||
    fail "Unauthorized-use notice missing"

echo
echo "--- Information Disclosure ---"

if grep -Eq '\\[nrlmsSv]' "${ISSUE}" 2>/dev/null; then
    fail "Login/OS escape sequence still exposed"
else
    pass "No login/OS escape sequences exposed"
fi

if grep -Eiq \
    'Ubuntu|Debian|Red Hat|Red Hat Enterprise Linux|RHEL|Linux [0-9]|kernel [0-9]' \
    "${ISSUE}" 2>/dev/null; then
    fail "OS/distribution information still exposed"
else
    pass "OS/distribution information not exposed"
fi

echo
echo "--- File Integrity ---"

if [[ -s "${ISSUE}" ]]; then
    pass "/etc/issue is not empty"
else
    fail "/etc/issue is empty"
fi

LINE_COUNT="$(wc -l < "${ISSUE}" 2>/dev/null || echo 0)"
if [[ "${LINE_COUNT}" =~ ^[0-9]+$ ]] && (( LINE_COUNT >= 20 )); then
    pass "Banner content length is valid (${LINE_COUNT} lines)"
else
    fail "Banner content appears incomplete (${LINE_COUNT:-0} lines)"
fi

echo
echo "=============================================="

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "=============================================="
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "=============================================="
    exit 1
fi
