#!/usr/bin/env bash
set -u

# Cross-platform Password Policy verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Expected policy:
# minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1
# history=5, PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=7
#
# Account lockout is verified separately.

PWQUALITY="/etc/security/pwquality.conf"
PWHISTORY_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"

EXPECTED_MINLEN="14"
EXPECTED_HISTORY="5"
EXPECTED_MAX_DAYS="90"
EXPECTED_MIN_DAYS="1"
EXPECTED_WARN_DAYS="7"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

get_eq_value() {
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

get_space_value() {
    local file="$1"
    local key="$2"

    awk -v key="${key}" '
        /^[[:space:]]*#/ { next }
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
echo " Cross-Platform Password Policy Verification"
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
    fail "Minimum length = ${MINLEN:-NOT SET}; expected ${EXPECTED_MINLEN}"

[[ "${DCREDIT}" == "-1" ]] &&
    pass "Digit required" ||
    fail "dcredit = ${DCREDIT:-NOT SET}; expected -1"

[[ "${UCREDIT}" == "-1" ]] &&
    pass "Uppercase required" ||
    fail "ucredit = ${UCREDIT:-NOT SET}; expected -1"

[[ "${LCREDIT}" == "-1" ]] &&
    pass "Lowercase required" ||
    fail "lcredit = ${LCREDIT:-NOT SET}; expected -1"

[[ "${OCREDIT}" == "-1" ]] &&
    pass "Special character required" ||
    fail "ocredit = ${OCREDIT:-NOT SET}; expected -1"

[[ "${ENFORCING}" == "1" ]] &&
    pass "Password quality enforcement active" ||
    fail "enforcing = ${ENFORCING:-NOT SET}; expected 1"

echo
echo "--- Password History ---"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_PASSWORD="/etc/pam.d/common-password"

    grep -Eq \
        '^[[:space:]]*password[[:space:]].*pam_pwquality\.so[[:space:]]+retry=5([[:space:]]|$)' \
        "${COMMON_PASSWORD}" &&
        pass "pam_pwquality active with retry=5" ||
        fail "pam_pwquality retry=5 not configured"

    grep -Eq \
        '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so.*remember=5' \
        "${COMMON_PASSWORD}" &&
        pass "Password history = last 5" ||
        fail "Password history last 5 not configured"
else
    SYSTEM_AUTH="/etc/pam.d/system-auth"
    PASSWORD_AUTH="/etc/pam.d/password-auth"

    command -v authselect >/dev/null 2>&1 &&
        pass "authselect available" ||
        fail "authselect not found"

    authselect check >/dev/null 2>&1 &&
        pass "authselect configuration valid" ||
        fail "authselect configuration invalid"

    authselect current 2>/dev/null | grep -qw 'with-pwhistory' &&
        pass "authselect with-pwhistory enabled" ||
        fail "authselect with-pwhistory disabled"

    grep -Eq 'pam_pwhistory\.so' "${SYSTEM_AUTH}" 2>/dev/null &&
        grep -Eq 'pam_pwhistory\.so' "${PASSWORD_AUTH}" 2>/dev/null &&
        pass "pam_pwhistory active in RHEL PAM stack" ||
        fail "pam_pwhistory missing from RHEL PAM stack"

    HISTORY="$(get_eq_value "${PWHISTORY_CONF}" remember)"
    [[ "${HISTORY}" == "${EXPECTED_HISTORY}" ]] &&
        pass "Password history = last ${HISTORY}" ||
        fail "Password history = ${HISTORY:-NOT SET}; expected ${EXPECTED_HISTORY}"
fi

echo
echo "--- Password Expiration Defaults ---"

MAX_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_MAX_DAYS)"
MIN_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_MIN_DAYS)"
WARN_DAYS="$(get_space_value "${LOGIN_DEFS}" PASS_WARN_AGE)"

[[ "${MAX_DAYS}" == "${EXPECTED_MAX_DAYS}" ]] &&
    pass "PASS_MAX_DAYS = ${MAX_DAYS}" ||
    fail "PASS_MAX_DAYS = ${MAX_DAYS:-NOT SET}; expected ${EXPECTED_MAX_DAYS}"

[[ "${MIN_DAYS}" == "${EXPECTED_MIN_DAYS}" ]] &&
    pass "PASS_MIN_DAYS = ${MIN_DAYS}" ||
    fail "PASS_MIN_DAYS = ${MIN_DAYS:-NOT SET}; expected ${EXPECTED_MIN_DAYS}"

[[ "${WARN_DAYS}" == "${EXPECTED_WARN_DAYS}" ]] &&
    pass "PASS_WARN_AGE = ${WARN_DAYS}" ||
    fail "PASS_WARN_AGE = ${WARN_DAYS:-NOT SET}; expected ${EXPECTED_WARN_DAYS}"

echo
echo "--- Existing Interactive Users ---"

UID_MIN="$(awk '$1=="UID_MIN"{print $2; exit}' "${LOGIN_DEFS}")"
UID_MIN="${UID_MIN:-1000}"
USER_COUNT=0

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "${uid}" -ge "${UID_MIN}" &&
          "${username}" != "nobody" &&
          "${shell}" != */nologin &&
          "${shell}" != */false ]]; then

        USER_COUNT=$((USER_COUNT + 1))

        CHAGE_OUTPUT="$(LC_ALL=C chage -l "${username}" 2>/dev/null || true)"

        USER_MIN="$(awk -F: '/Minimum number of days between password change/{gsub(/[[:space:]]/,"",$2);print $2;exit}' <<< "${CHAGE_OUTPUT}")"
        USER_MAX="$(awk -F: '/Maximum number of days between password change/{gsub(/[[:space:]]/,"",$2);print $2;exit}' <<< "${CHAGE_OUTPUT}")"
        USER_WARN="$(awk -F: '/Number of days of warning before password expires/{gsub(/[[:space:]]/,"",$2);print $2;exit}' <<< "${CHAGE_OUTPUT}")"

        if [[ "${USER_MAX}" == "${EXPECTED_MAX_DAYS}" &&
              "${USER_MIN}" == "${EXPECTED_MIN_DAYS}" &&
              "${USER_WARN}" == "${EXPECTED_WARN_DAYS}" ]]; then
            pass "${username}: expiry policy = ${USER_MAX}/${USER_MIN}/${USER_WARN}"
        else
            fail "${username}: expiry policy = ${USER_MAX:-?}/${USER_MIN:-?}/${USER_WARN:-?}; expected ${EXPECTED_MAX_DAYS}/${EXPECTED_MIN_DAYS}/${EXPECTED_WARN_DAYS}"
        fi
    fi
done < /etc/passwd

(( USER_COUNT > 0 )) ||
    fail "No interactive users found for chage verification"

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
