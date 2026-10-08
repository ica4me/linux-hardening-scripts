#!/usr/bin/env bash
set -u

# Cross-platform auditd verification.
#
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x

RULES_FILE="/etc/audit/rules.d/50-linux-hardening.rules"

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
        FAMILY="debian"
        EXPECTED_PACKAGE_1="auditd"
        EXPECTED_PACKAGE_2="audispd-plugins"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        FAMILY="debian"
        EXPECTED_PACKAGE_1="auditd"
        EXPECTED_PACKAGE_2="audispd-plugins"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        FAMILY="rhel"
        EXPECTED_PACKAGE_1="audit"
        EXPECTED_PACKAGE_2="audispd-plugins"
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        HAS_B32=1
        ;;
    aarch64|arm64)
        HAS_B32=0
        ;;
    *)
        echo "[FAIL] Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

check_package() {
    local package="$1"

    if [[ "${FAMILY}" == "debian" ]]; then
        dpkg-query -W -f='${Status}' "${package}" 2>/dev/null |
            grep -q "install ok installed"
    else
        rpm -q "${package}" >/dev/null 2>&1
    fi
}

check_rule_key() {
    local key="$1"

    if auditctl -l 2>/dev/null |
        grep -Eq "key=${key}|-k[[:space:]]+${key}"
    then
        pass "Audit key active: ${key}"
    else
        fail "Audit key inactive: ${key}"
    fi
}

echo "==========================================="
echo " Cross-Platform Auditd Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "==========================================="
echo

echo "--- Packages ---"

check_package "${EXPECTED_PACKAGE_1}" &&
    pass "${EXPECTED_PACKAGE_1} installed" ||
    fail "${EXPECTED_PACKAGE_1} not installed"

check_package "${EXPECTED_PACKAGE_2}" &&
    pass "${EXPECTED_PACKAGE_2} installed" ||
    fail "${EXPECTED_PACKAGE_2} not installed"

echo
echo "--- Service ---"

systemctl is-active --quiet auditd &&
    pass "auditd service active" ||
    fail "auditd service inactive"

if systemctl is-enabled --quiet auditd 2>/dev/null; then
    pass "auditd service enabled"
else
    STATE="$(systemctl is-enabled auditd 2>/dev/null || true)"
    fail "auditd service state = ${STATE:-unknown}"
fi

echo
echo "--- Audit Status ---"

AUDIT_ENABLED="$(
    auditctl -s 2>/dev/null |
        awk '$1=="enabled" {print $2}'
)"

if [[ "${AUDIT_ENABLED}" == "1" || "${AUDIT_ENABLED}" == "2" ]]; then
    pass "Kernel auditing enabled"
else
    fail "Kernel auditing disabled"
fi

LOST="$(
    auditctl -s 2>/dev/null |
        awk '$1=="lost" {print $2}'
)"

if [[ "${LOST:-}" =~ ^[0-9]+$ && "${LOST}" -eq 0 ]]; then
    pass "Audit lost events = 0"
else
    fail "Audit lost events = ${LOST:-UNKNOWN}"
fi

echo
echo "--- Rules File ---"

[[ -f "${RULES_FILE}" ]] &&
    pass "Audit rules file exists: ${RULES_FILE}" ||
    fail "Audit rules file missing: ${RULES_FILE}"

OWNER="$(stat -c '%U:%G' "${RULES_FILE}" 2>/dev/null)"
MODE="$(stat -c '%a' "${RULES_FILE}" 2>/dev/null)"

[[ "${OWNER}" == "root:root" ]] &&
    pass "Rules owner = root:root" ||
    fail "Rules owner = ${OWNER:-UNKNOWN}"

[[ "${MODE}" == "640" ]] &&
    pass "Rules permission = 640" ||
    fail "Rules permission = ${MODE:-UNKNOWN}"

echo
echo "--- Reference Rule Coverage ---"

grep -Eq -- '-F arch=b64 .*adjtimex.*settimeofday.*-k time-change' "${RULES_FILE}" &&
    pass "b64 adjtimex/settimeofday rule configured" ||
    fail "b64 adjtimex/settimeofday rule missing"

grep -Eq -- '-F arch=b64 .*clock_settime.*-k time-change' "${RULES_FILE}" &&
    pass "b64 clock_settime rule configured" ||
    fail "b64 clock_settime rule missing"

if (( HAS_B32 == 1 )); then
    grep -Eq -- '-F arch=b32 .*adjtimex.*settimeofday.*stime.*-k time-change' "${RULES_FILE}" &&
        pass "b32 adjtimex/settimeofday/stime rule configured" ||
        fail "b32 adjtimex/settimeofday/stime rule missing"

    grep -Eq -- '-F arch=b32 .*clock_settime.*-k time-change' "${RULES_FILE}" &&
        pass "b32 clock_settime rule configured" ||
        fail "b32 clock_settime rule missing"
fi

echo
echo "--- Active Audit Rules ---"

check_rule_key "time-change"
check_rule_key "identity"
check_rule_key "system-locale"
check_rule_key "MAC-policy"
check_rule_key "logins"
check_rule_key "session"
check_rule_key "perm_mod"
check_rule_key "access"
check_rule_key "delete"
check_rule_key "scope"
check_rule_key "actions"

echo
echo "--- Rule Compilation ---"

if augenrules --check >/dev/null 2>&1; then
    pass "Audit rules syntax valid"
else
    fail "Audit rules syntax invalid"
fi

echo
echo "--- Audit Log ---"

if [[ -f /var/log/audit/audit.log ]]; then
    pass "/var/log/audit/audit.log exists"
else
    fail "/var/log/audit/audit.log missing"
fi

echo
echo "--- Tools ---"

command -v auditctl >/dev/null 2>&1 &&
    pass "auditctl available" ||
    fail "auditctl not found"

command -v ausearch >/dev/null 2>&1 &&
    pass "ausearch available" ||
    fail "ausearch not found"

command -v augenrules >/dev/null 2>&1 &&
    pass "augenrules available" ||
    fail "augenrules not found"

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
