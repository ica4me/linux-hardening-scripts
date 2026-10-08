#!/usr/bin/env bash
set -u

# Cross-platform auditd verification.
#
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Verifies the separate rule-file layout used by the reference policy.

RULES_DIR="/etc/audit/rules.d"

EXPECTED_FILES=(
    "50-time-change.rules"
    "50-identity.rules"
    "50-system-locale.rules"
    "50-MAC-policy.rules"
    "50-logins.rules"
    "50-session.rules"
    "50-perm_mod.rules"
    "50-access.rules"
    "50-delete.rules"
    "50-scope.rules"
    "50-actions.rules"
)

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
        MAC_TYPE="apparmor"
        PACKAGE_1="auditd"
        PACKAGE_2="audispd-plugins"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        FAMILY="debian"
        MAC_TYPE="apparmor"
        PACKAGE_1="auditd"
        PACKAGE_2="audispd-plugins"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        FAMILY="rhel"
        MAC_TYPE="selinux"
        PACKAGE_1="audit"
        PACKAGE_2="audispd-plugins"
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

check_active_key() {
    local key="$1"
    if auditctl -l 2>/dev/null | grep -Eq "key=${key}|-k[[:space:]]+${key}"; then
        pass "Audit key active: ${key}"
    else
        fail "Audit key inactive: ${key}"
    fi
}

check_line() {
    local file="$1"
    local pattern="$2"
    local description="$3"

    if grep -Fqx -- "${pattern}" "${file}" 2>/dev/null; then
        pass "${description}"
    else
        fail "${description}"
    fi
}

echo "============================================================"
echo " Cross-Platform Auditd Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "============================================================"
echo

echo "--- Packages ---"

check_package "${PACKAGE_1}" &&
    pass "${PACKAGE_1} installed" ||
    fail "${PACKAGE_1} not installed"

check_package "${PACKAGE_2}" &&
    pass "${PACKAGE_2} installed" ||
    fail "${PACKAGE_2} not installed"

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

AUDIT_ENABLED="$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2; exit}')"
if [[ "${AUDIT_ENABLED}" == "1" || "${AUDIT_ENABLED}" == "2" ]]; then
    pass "Kernel auditing enabled = ${AUDIT_ENABLED}"
else
    fail "Kernel auditing disabled or unavailable"
fi

LOST="$(auditctl -s 2>/dev/null | awk '$1=="lost"{print $2; exit}')"
if [[ "${LOST:-}" =~ ^[0-9]+$ && "${LOST}" -eq 0 ]]; then
    pass "Audit lost events = 0"
else
    fail "Audit lost events = ${LOST:-UNKNOWN}"
fi

echo
echo "--- Managed Rule Files ---"

for file in "${EXPECTED_FILES[@]}"; do
    path="${RULES_DIR}/${file}"

    if [[ -f "${path}" ]]; then
        pass "${file} exists"

        OWNER="$(stat -c '%U:%G' "${path}" 2>/dev/null)"
        MODE="$(stat -c '%a' "${path}" 2>/dev/null)"

        [[ "${OWNER}" == "root:root" ]] &&
            pass "${file} owner = root:root" ||
            fail "${file} owner = ${OWNER:-UNKNOWN}"

        [[ "${MODE}" == "640" ]] &&
            pass "${file} permission = 640" ||
            fail "${file} permission = ${MODE:-UNKNOWN}"
    else
        fail "${file} missing"
    fi
done

echo
echo "--- Time Change Rules ---"

TIME="${RULES_DIR}/50-time-change.rules"

check_line "${TIME}" \
    "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" \
    "b64 adjtimex/settimeofday configured"

check_line "${TIME}" \
    "-a always,exit -F arch=b64 -S clock_settime -k time-change" \
    "b64 clock_settime configured"

if (( HAS_B32 == 1 )); then
    check_line "${TIME}" \
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" \
        "b32 adjtimex/settimeofday/stime configured"

    check_line "${TIME}" \
        "-a always,exit -F arch=b32 -S clock_settime -k time-change" \
        "b32 clock_settime configured"
fi

check_line "${TIME}" \
    "-w /etc/localtime -p wa -k time-change" \
    "/etc/localtime watch configured"

echo
echo "--- Identity Rules ---"

IDENTITY="${RULES_DIR}/50-identity.rules"
for path in /etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd; do
    check_line "${IDENTITY}" "-w ${path} -p wa -k identity" "${path} identity watch configured"
done

echo
echo "--- System Locale Rules ---"

LOCALE="${RULES_DIR}/50-system-locale.rules"

check_line "${LOCALE}" \
    "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" \
    "b64 hostname/domain rule configured"

if (( HAS_B32 == 1 )); then
    check_line "${LOCALE}" \
        "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" \
        "b32 hostname/domain rule configured"
fi

for path in /etc/issue /etc/issue.net /etc/hosts; do
    check_line "${LOCALE}" "-w ${path} -p wa -k system-locale" "${path} system-locale watch configured"
done

if [[ -e /etc/network ]]; then
    check_line "${LOCALE}" "-w /etc/network -p wa -k system-locale" "/etc/network watch configured"
fi

echo
echo "--- MAC Policy Rules ---"

MAC="${RULES_DIR}/50-MAC-policy.rules"

if [[ "${MAC_TYPE}" == "apparmor" ]]; then
    check_line "${MAC}" "-w /etc/apparmor/ -p wa -k MAC-policy" "/etc/apparmor watch configured"
    check_line "${MAC}" "-w /etc/apparmor.d/ -p wa -k MAC-policy" "/etc/apparmor.d watch configured"
else
    check_line "${MAC}" "-w /etc/selinux/ -p wa -k MAC-policy" "/etc/selinux watch configured"
fi

echo
echo "--- Login and Session Rules ---"

LOGINS="${RULES_DIR}/50-logins.rules"
SESSION="${RULES_DIR}/50-session.rules"

for path in /var/log/faillog /var/log/lastlog /var/log/tallylog; do
    check_line "${LOGINS}" "-w ${path} -p wa -k logins" "${path} login watch configured"
done

check_line "${SESSION}" "-w /var/run/utmp -p wa -k session" "/var/run/utmp session watch configured"
check_line "${SESSION}" "-w /var/log/wtmp -p wa -k logins" "/var/log/wtmp watch configured"
check_line "${SESSION}" "-w /var/log/btmp -p wa -k logins" "/var/log/btmp watch configured"

echo
echo "--- Active Audit Keys ---"

for key in time-change identity system-locale MAC-policy logins session perm_mod access delete scope actions; do
    check_active_key "${key}"
done

echo
echo "--- Rule Compilation ---"

if augenrules --check >/dev/null 2>&1; then
    pass "Audit rules compilation valid"
else
    fail "Audit rules compilation invalid"
fi

echo
echo "--- Legacy Aggregate Rules ---"

if [[ ! -e "${RULES_DIR}/50-linux-hardening.rules" &&
      ! -e "${RULES_DIR}/50-dbalance-hardening.rules" ]]; then
    pass "Legacy aggregate rule files are absent"
else
    fail "Legacy aggregate rule file still exists and may cause duplicate rules"
fi

echo
echo "--- Audit Log and Tools ---"

[[ -f /var/log/audit/audit.log ]] &&
    pass "/var/log/audit/audit.log exists" ||
    fail "/var/log/audit/audit.log missing"

for tool in auditctl ausearch augenrules; do
    command -v "${tool}" >/dev/null 2>&1 &&
        pass "${tool} available" ||
        fail "${tool} not found"
done

echo
echo "============================================================"

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "============================================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "============================================================"
    exit 1
fi
