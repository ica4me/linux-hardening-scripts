#!/usr/bin/env bash
set -u

# Cross-platform SSH/session policy verification.
# Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-dbalance-session-security.conf"
TIMEOUT_FILE="/etc/profile.d/99-session-timeout.sh"

EXPECTED_INTERVAL="${CLIENT_ALIVE_INTERVAL:-300}"
EXPECTED_COUNT="${CLIENT_ALIVE_COUNT_MAX:-3}"
EXPECTED_TIMEOUT="${SESSION_TIMEOUT:-900}"

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
        SSH_SERVICE="ssh"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        SSH_SERVICE="ssh"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        SSH_SERVICE="sshd"
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

SSHD_BIN="$(command -v sshd || true)"
[[ -n "${SSHD_BIN}" ]] || SSHD_BIN="/usr/sbin/sshd"

echo "================================================"
echo " DBalance SSH & Session Policy Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "================================================"
echo

echo "--- SSH Service ---"

if systemctl is-active --quiet "${SSH_SERVICE}"; then
    pass "${SSH_SERVICE} service active"
else
    fail "${SSH_SERVICE} service inactive"
fi

if [[ -x "${SSHD_BIN}" ]] && "${SSHD_BIN}" -t 2>/dev/null; then
    pass "SSH configuration syntax valid"
else
    fail "SSH configuration syntax invalid"
fi

echo
echo "--- Main SSH Configuration ---"

grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+no[[:space:]]*$' "${SSHD_CONFIG}" &&
    pass "PasswordAuthentication = no" ||
    fail "PasswordAuthentication is not set to no"

grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+prohibit-password[[:space:]]*$' "${SSHD_CONFIG}" &&
    pass "PermitRootLogin = prohibit-password" ||
    fail "PermitRootLogin is not prohibit-password"

grep -Eq '^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+no[[:space:]]*$' "${SSHD_CONFIG}" &&
    pass "KbdInteractiveAuthentication = no" ||
    fail "KbdInteractiveAuthentication is not no"

grep -Eq "^[[:space:]]*ClientAliveInterval[[:space:]]+${EXPECTED_INTERVAL}[[:space:]]*$" "${SSHD_CONFIG}" &&
    pass "ClientAliveInterval = ${EXPECTED_INTERVAL}" ||
    fail "ClientAliveInterval is incorrect"

grep -Eq "^[[:space:]]*ClientAliveCountMax[[:space:]]+${EXPECTED_COUNT}[[:space:]]*$" "${SSHD_CONFIG}" &&
    pass "ClientAliveCountMax = ${EXPECTED_COUNT}" ||
    fail "ClientAliveCountMax is incorrect"

echo
echo "--- Effective SSH Configuration ---"

EFFECTIVE="$("${SSHD_BIN}" -T 2>/dev/null || true)"

grep -Eq '^passwordauthentication no$' <<< "${EFFECTIVE}" &&
    pass "Effective PasswordAuthentication = no" ||
    fail "Effective PasswordAuthentication is not no"

grep -Eq '^permitrootlogin prohibit-password$' <<< "${EFFECTIVE}" &&
    pass "Effective PermitRootLogin = prohibit-password" ||
    fail "Effective PermitRootLogin is not prohibit-password"

grep -Eq '^kbdinteractiveauthentication no$' <<< "${EFFECTIVE}" &&
    pass "Effective KbdInteractiveAuthentication = no" ||
    fail "Effective KbdInteractiveAuthentication is not no"

grep -Eq "^clientaliveinterval ${EXPECTED_INTERVAL}$" <<< "${EFFECTIVE}" &&
    pass "Effective ClientAliveInterval = ${EXPECTED_INTERVAL}" ||
    fail "Effective ClientAliveInterval is incorrect"

grep -Eq "^clientalivecountmax ${EXPECTED_COUNT}$" <<< "${EFFECTIVE}" &&
    pass "Effective ClientAliveCountMax = ${EXPECTED_COUNT}" ||
    fail "Effective ClientAliveCountMax is incorrect"

echo
echo "--- Interactive Session Timeout ---"

if [[ -f "${TIMEOUT_FILE}" ]] &&
   grep -Eq "^[[:space:]]*TMOUT=${EXPECTED_TIMEOUT}[[:space:]]*$" "${TIMEOUT_FILE}"; then
    pass "Interactive session timeout = ${EXPECTED_TIMEOUT} seconds"
else
    fail "TMOUT=${EXPECTED_TIMEOUT} not configured"
fi

grep -Eq '^[[:space:]]*readonly[[:space:]]+TMOUT[[:space:]]*$' "${TIMEOUT_FILE}" 2>/dev/null &&
    pass "TMOUT is readonly" ||
    fail "TMOUT is not readonly"

grep -Eq '^[[:space:]]*export[[:space:]]+TMOUT[[:space:]]*$' "${TIMEOUT_FILE}" 2>/dev/null &&
    pass "TMOUT is exported" ||
    fail "TMOUT is not exported"

echo
echo "--- File Security ---"

OWNER="$(stat -c '%U:%G' "${SSHD_CONFIG}" 2>/dev/null)"
MODE="$(stat -c '%a' "${SSHD_CONFIG}" 2>/dev/null)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "sshd_config owner = root:root" ||
    fail "sshd_config owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "600" ]] &&
    pass "sshd_config permission = 600" ||
    fail "sshd_config permission = ${MODE:-UNKNOWN}"

if [[ -f "${SSHD_DROPIN}" ]]; then
    DROPIN_OWNER="$(stat -c '%U:%G' "${SSHD_DROPIN}" 2>/dev/null)"
    DROPIN_MODE="$(stat -c '%a' "${SSHD_DROPIN}" 2>/dev/null)"

    [[ "${DROPIN_OWNER}" == "root:root" ]] &&
        pass "SSH drop-in owner = root:root" ||
        fail "SSH drop-in owner = ${DROPIN_OWNER:-UNKNOWN}"

    [[ "${DROPIN_MODE}" == "600" ]] &&
        pass "SSH drop-in permission = 600" ||
        fail "SSH drop-in permission = ${DROPIN_MODE:-UNKNOWN}"
else
    fail "SSH drop-in file missing"
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
