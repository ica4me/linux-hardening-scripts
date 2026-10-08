#!/usr/bin/env bash
set -u

# Cross-platform Account Lockout verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Expected default policy:
# deny=3
# fail_interval=900
# unlock_time=1800

EXPECTED_DENY="${LOCKOUT_DENY:-3}"
EXPECTED_FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
EXPECTED_UNLOCK_TIME="${UNLOCK_TIME:-1800}"

FAILLOCK_CONF="/etc/security/faillock.conf"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

get_value() {
    local file="$1"
    local key="$2"

    awk -F= -v key="${key}" '
        /^[[:space:]]*#/ { next }
        {
            lhs=$1
            gsub(/[[:space:]]/, "", lhs)
            if (lhs == key) {
                rhs=$2
                gsub(/[[:space:]]/, "", rhs)
                value=rhs
            }
        }
        END { if (value != "") print value }
    ' "${file}" 2>/dev/null
}

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
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        FAMILY="debian"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        FAMILY="rhel"
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

echo "================================================"
echo " Cross-Platform Account Lockout Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "================================================"
echo

echo "--- Lockout Policy ---"

DENY="$(get_value "${FAILLOCK_CONF}" deny)"
FAIL_INTERVAL_VALUE="$(get_value "${FAILLOCK_CONF}" fail_interval)"
UNLOCK_TIME_VALUE="$(get_value "${FAILLOCK_CONF}" unlock_time)"

[[ "${DENY}" == "${EXPECTED_DENY}" ]] &&
    pass "Failure threshold = ${DENY}" ||
    fail "deny = ${DENY:-NOT SET}; expected ${EXPECTED_DENY}"

[[ "${FAIL_INTERVAL_VALUE}" == "${EXPECTED_FAIL_INTERVAL}" ]] &&
    pass "Failure window = ${FAIL_INTERVAL_VALUE} seconds" ||
    fail "fail_interval = ${FAIL_INTERVAL_VALUE:-NOT SET}; expected ${EXPECTED_FAIL_INTERVAL}"

[[ "${UNLOCK_TIME_VALUE}" == "${EXPECTED_UNLOCK_TIME}" ]] &&
    pass "Temporary ban = ${UNLOCK_TIME_VALUE} seconds (30 minutes)" ||
    fail "unlock_time = ${UNLOCK_TIME_VALUE:-NOT SET}; expected ${EXPECTED_UNLOCK_TIME}"

echo
echo "--- PAM Integration ---"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_AUTH="/etc/pam.d/common-auth"
    COMMON_ACCOUNT="/etc/pam.d/common-account"

    grep -Eq 'pam_faillock\.so[[:space:]]+preauth' "${COMMON_AUTH}" &&
        pass "pam_faillock preauth active" ||
        fail "pam_faillock preauth inactive"

    grep -Eq 'pam_faillock\.so[[:space:]]+authfail' "${COMMON_AUTH}" &&
        pass "pam_faillock authfail active" ||
        fail "pam_faillock authfail inactive"

    grep -Eq 'pam_faillock\.so[[:space:]]+authsucc' "${COMMON_AUTH}" &&
        pass "pam_faillock authsucc active" ||
        fail "pam_faillock authsucc inactive"

    grep -Eq \
        '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so' \
        "${COMMON_ACCOUNT}" &&
        pass "pam_faillock account module active" ||
        fail "pam_faillock account module inactive"
else
    command -v authselect >/dev/null 2>&1 &&
        pass "authselect available" ||
        fail "authselect not found"

    authselect check >/dev/null 2>&1 &&
        pass "authselect configuration valid" ||
        fail "authselect configuration invalid"

    authselect current 2>/dev/null | grep -qw 'with-faillock' &&
        pass "authselect with-faillock enabled" ||
        fail "authselect with-faillock disabled"

    grep -Eq 'pam_faillock\.so' /etc/pam.d/system-auth 2>/dev/null &&
        grep -Eq 'pam_faillock\.so' /etc/pam.d/password-auth 2>/dev/null &&
        pass "pam_faillock active in RHEL PAM stack" ||
        fail "pam_faillock missing from RHEL PAM stack"
fi

echo
echo "--- Module & Tool ---"

if find /lib /usr/lib \
    -type f \
    -name pam_faillock.so \
    -print \
    -quit 2>/dev/null |
    grep -q .
then
    pass "pam_faillock.so available"
else
    fail "pam_faillock.so not found"
fi

command -v faillock >/dev/null 2>&1 &&
    pass "faillock command available" ||
    fail "faillock command not found"

echo
echo "--- Current Failure Database ---"

if command -v faillock >/dev/null 2>&1; then
    faillock 2>/dev/null | sed -n '1,20p' || true
fi

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
