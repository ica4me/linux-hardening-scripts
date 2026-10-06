#!/usr/bin/env bash
set -u

# Cross-platform password policy verification:
# Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x

PWQUALITY="/etc/security/pwquality.conf"
PWHISTORY_CONF="/etc/security/pwhistory.conf"
FAILLOCK="/etc/security/faillock.conf"
LOGIN_DEFS="/etc/login.defs"

EXPECTED_MINLEN=12
EXPECTED_HISTORY=5
EXPECTED_LOCKOUT_DENY="${LOCKOUT_DENY:-5}"
EXPECTED_LOCKOUT_TIME="${LOCKOUT_TIME:-600}"
EXPECTED_FAIL_INTERVAL="${FAIL_INTERVAL:-900}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

get_eq_value() {
    local file="$1" key="$2"
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

get_space_value() {
    local file="$1" key="$2"
    awk -v key="${key}" '
        $1 == key { value=$2 }
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

echo "===================================================="
echo " DBalance Cross-Platform Password Policy Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "===================================================="
echo

echo "--- Password Quality ---"

MINLEN="$(get_eq_value "${PWQUALITY}" minlen)"
DCREDIT="$(get_eq_value "${PWQUALITY}" dcredit)"
UCREDIT="$(get_eq_value "${PWQUALITY}" ucredit)"
LCREDIT="$(get_eq_value "${PWQUALITY}" lcredit)"
OCREDIT="$(get_eq_value "${PWQUALITY}" ocredit)"
ENFORCING="$(get_eq_value "${PWQUALITY}" enforcing)"

[[ "${MINLEN}" == "${EXPECTED_MINLEN}" ]] &&
    pass "Minimum length = ${MINLEN}" ||
    fail "Minimum length = ${MINLEN:-NOT SET}"

[[ "${DCREDIT}" == "-1" ]] &&
    pass "Digit required" ||
    fail "dcredit = ${DCREDIT:-NOT SET}"

[[ "${UCREDIT}" == "-1" ]] &&
    pass "Uppercase required" ||
    fail "ucredit = ${UCREDIT:-NOT SET}"

[[ "${LCREDIT}" == "-1" ]] &&
    pass "Lowercase required" ||
    fail "lcredit = ${LCREDIT:-NOT SET}"

[[ "${OCREDIT}" == "0" ]] &&
    pass "Special character not required" ||
    fail "ocredit = ${OCREDIT:-NOT SET}"

[[ "${ENFORCING}" == "1" ]] &&
    pass "Password quality enforcement active" ||
    fail "enforcing = ${ENFORCING:-NOT SET}"

echo
echo "--- Password History ---"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_PASSWORD="/etc/pam.d/common-password"

    grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "${COMMON_PASSWORD}" &&
        pass "pam_pwquality active" ||
        fail "pam_pwquality inactive"

    grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so.*remember=5' "${COMMON_PASSWORD}" &&
        pass "Password history = last 5" ||
        fail "Password history last 5 not configured"
else
    SYSTEM_AUTH="/etc/pam.d/system-auth"
    PASSWORD_AUTH="/etc/pam.d/password-auth"

    authselect check >/dev/null 2>&1 &&
        pass "authselect configuration valid" ||
        fail "authselect configuration invalid"

    authselect current 2>/dev/null | grep -qw 'with-pwhistory' &&
        pass "authselect with-pwhistory enabled" ||
        fail "authselect with-pwhistory disabled"

    grep -Eq 'pam_pwhistory\.so' "${SYSTEM_AUTH}" &&
        grep -Eq 'pam_pwhistory\.so' "${PASSWORD_AUTH}" &&
        pass "pam_pwhistory active in RHEL PAM stack" ||
        fail "pam_pwhistory missing from RHEL PAM stack"

    HISTORY="$(get_eq_value "${PWHISTORY_CONF}" remember)"
    [[ "${HISTORY}" == "${EXPECTED_HISTORY}" ]] &&
        pass "Password history = last ${HISTORY}" ||
        fail "Password history = ${HISTORY:-NOT SET}"
fi

echo
echo "--- Password Expiration ---"

MAX_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_MAX_DAYS)"
MIN_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_MIN_DAYS)"
WARN_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_WARN_AGE)"

[[ "${MAX_DAYS}" == "-1" ]] &&
    pass "PASS_MAX_DAYS = -1 (never expires)" ||
    fail "PASS_MAX_DAYS = ${MAX_DAYS:-NOT SET}"

[[ "${MIN_DAYS}" == "0" ]] &&
    pass "PASS_MIN_DAYS = 0" ||
    fail "PASS_MIN_DAYS = ${MIN_DAYS:-NOT SET}"

[[ "${WARN_DAYS}" == "-1" ]] &&
    pass "PASS_WARN_AGE = -1" ||
    fail "PASS_WARN_AGE = ${WARN_DAYS:-NOT SET}"

UID_MIN="$(awk '$1=="UID_MIN"{print $2; exit}' "${LOGIN_DEFS}")"
UID_MIN="${UID_MIN:-1000}"

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "${uid}" -ge "${UID_MIN}" &&
          "${username}" != "nobody" &&
          "${shell}" != */nologin &&
          "${shell}" != */false ]]; then

        USER_MAX="$(
            LC_ALL=C chage -l "${username}" 2>/dev/null |
            awk -F: '/Maximum number of days between password change/ {
                gsub(/[[:space:]]/, "", $2)
                print $2
            }'
        )"

        [[ "${USER_MAX}" == "-1" ]] &&
            pass "${username}: password never expires" ||
            fail "${username}: maximum password age = ${USER_MAX:-UNKNOWN}"
    fi
done < /etc/passwd

echo
echo "--- Temporary Login Ban ---"

DENY="$(get_eq_value "${FAILLOCK}" deny)"
FAIL_INTERVAL_VALUE="$(get_eq_value "${FAILLOCK}" fail_interval)"
UNLOCK_TIME="$(get_eq_value "${FAILLOCK}" unlock_time)"

[[ "${DENY}" == "${EXPECTED_LOCKOUT_DENY}" ]] &&
    pass "Failure threshold = ${DENY}" ||
    fail "deny = ${DENY:-NOT SET}"

[[ "${FAIL_INTERVAL_VALUE}" == "${EXPECTED_FAIL_INTERVAL}" ]] &&
    pass "Failure observation window = ${FAIL_INTERVAL_VALUE}s" ||
    fail "fail_interval = ${FAIL_INTERVAL_VALUE:-NOT SET}"

[[ "${UNLOCK_TIME}" == "${EXPECTED_LOCKOUT_TIME}" ]] &&
    pass "Temporary ban = ${UNLOCK_TIME}s (10 minutes)" ||
    fail "unlock_time = ${UNLOCK_TIME:-NOT SET}"

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

    grep -Eq '^[[:space:]]*account[[:space:]].*pam_faillock\.so' "${COMMON_ACCOUNT}" &&
        pass "pam_faillock account module active" ||
        fail "pam_faillock account module inactive"
else
    authselect current 2>/dev/null | grep -qw 'with-faillock' &&
        pass "authselect with-faillock enabled" ||
        fail "authselect with-faillock disabled"

    grep -Eq 'pam_faillock\.so' /etc/pam.d/system-auth &&
        grep -Eq 'pam_faillock\.so' /etc/pam.d/password-auth &&
        pass "pam_faillock active in RHEL PAM stack" ||
        fail "pam_faillock missing from RHEL PAM stack"
fi

echo
echo "===================================================="

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "===================================================="
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "===================================================="
    exit 1
fi
