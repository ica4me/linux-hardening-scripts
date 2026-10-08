#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform Password Policy hardening.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# - Minimum password length: 14
# - At least 1 digit
# - At least 1 uppercase character
# - At least 1 lowercase character
# - At least 1 special character
# - Password history: last 5
# - Maximum password age: 90 days
# - Minimum password age: 1 day
# - Warning before expiry: 7 days
#
# Account lockout is intentionally handled by:
# account_lockout_apply_multios.sh

MINLEN="14"
HISTORY="5"
PASS_MAX_DAYS="90"
PASS_MIN_DAYS="1"
PASS_WARN_AGE="7"

PWQUALITY="/etc/security/pwquality.conf"
PWHISTORY_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"

BACKUP_ROOT="/var/backups/password-policy"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"

case "${OS_ID}" in
    ubuntu)
        [[ "${OS_VER}" == "22.04" || "${OS_VER}" == "24.04" ]] ||
            fail "Unsupported Ubuntu version: ${OS_VER}"
        FAMILY="debian"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] ||
            fail "Unsupported Debian version: ${OS_VER}"
        FAMILY="debian"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] ||
            fail "Unsupported RHEL version: ${OS_VER}"
        FAMILY="rhel"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        ;;
esac

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying Password Policy ==="

mkdir -p "${BACKUP_DIR}"

backup_if_exists() {
    local file="$1"
    if [[ -e "${file}" ]]; then
        cp -a "${file}" "${BACKUP_DIR}/$(basename "${file}")"
    fi
}

set_eq_value() {
    local file="$1"
    local key="$2"
    local value="$3"

    touch "${file}"

    if grep -Eq "^[[:space:]#]*${key}[[:space:]]*=" "${file}"; then
        sed -Ei \
            "s|^[[:space:]#]*${key}[[:space:]]*=.*$|${key} = ${value}|" \
            "${file}"
    else
        printf '\n%s = %s\n' "${key}" "${value}" >> "${file}"
    fi
}

set_space_value() {
    local file="$1"
    local key="$2"
    local value="$3"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "${file}"; then
        sed -Ei \
            "s|^[[:space:]]*${key}[[:space:]]+.*$|${key}   ${value}|" \
            "${file}"
    else
        printf '\n%s   %s\n' "${key}" "${value}" >> "${file}"
    fi
}

backup_if_exists "${PWQUALITY}"
backup_if_exists "${PWHISTORY_CONF}"
backup_if_exists "${LOGIN_DEFS}"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_PASSWORD="/etc/pam.d/common-password"

    backup_if_exists "${COMMON_PASSWORD}"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq libpam-pwquality libpam-modules

    [[ -f "${COMMON_PASSWORD}" ]] ||
        fail "${COMMON_PASSWORD} not found."
else
    SYSTEM_AUTH="/etc/pam.d/system-auth"
    PASSWORD_AUTH="/etc/pam.d/password-auth"

    backup_if_exists "${SYSTEM_AUTH}"
    backup_if_exists "${PASSWORD_AUTH}"

    dnf install -y -q libpwquality pam authselect

    command -v authselect >/dev/null 2>&1 ||
        fail "authselect not found."

    authselect check >/dev/null 2>&1 ||
        fail "Current authselect configuration is invalid."

    authselect current >/dev/null 2>&1 ||
        fail "No active authselect profile found."
fi

# Password complexity.
set_eq_value "${PWQUALITY}" "minlen" "${MINLEN}"
set_eq_value "${PWQUALITY}" "dcredit" "-1"
set_eq_value "${PWQUALITY}" "ucredit" "-1"
set_eq_value "${PWQUALITY}" "lcredit" "-1"
set_eq_value "${PWQUALITY}" "ocredit" "-1"
set_eq_value "${PWQUALITY}" "enforcing" "1"

# Password history.
if [[ "${FAMILY}" == "debian" ]]; then
    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "${COMMON_PASSWORD}"; then
        sed -Ei \
            's|^[[:space:]]*password[[:space:]].*pam_pwquality\.so.*$|password        requisite                       pam_pwquality.so retry=5|' \
            "${COMMON_PASSWORD}"
    else
        sed -i \
            '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password        requisite                       pam_pwquality.so retry=5' \
            "${COMMON_PASSWORD}"
    fi

    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so' "${COMMON_PASSWORD}"; then
        sed -Ei \
            's|^[[:space:]]*password[[:space:]].*pam_pwhistory\.so.*$|password        required                        pam_pwhistory.so remember=5|' \
            "${COMMON_PASSWORD}"
    else
        sed -i \
            '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password        required                        pam_pwhistory.so remember=5' \
            "${COMMON_PASSWORD}"
    fi
else
    set_eq_value "${PWHISTORY_CONF}" "remember" "${HISTORY}"

    if ! authselect current | grep -qw 'with-pwhistory'; then
        authselect enable-feature with-pwhistory -b >/dev/null
    fi

    authselect apply-changes >/dev/null
fi

# Password expiration defaults for newly created users.
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "${PASS_MAX_DAYS}"
set_space_value "${LOGIN_DEFS}" "PASS_MIN_DAYS" "${PASS_MIN_DAYS}"
set_space_value "${LOGIN_DEFS}" "PASS_WARN_AGE" "${PASS_WARN_AGE}"

# Apply expiration policy to existing interactive users.
UID_MIN="$(awk '$1=="UID_MIN"{print $2; exit}' "${LOGIN_DEFS}")"
UID_MIN="${UID_MIN:-1000}"

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "${uid}" -ge "${UID_MIN}" &&
          "${username}" != "nobody" &&
          "${shell}" != */nologin &&
          "${shell}" != */false ]]; then

        chage \
            -M "${PASS_MAX_DAYS}" \
            -m "${PASS_MIN_DAYS}" \
            -W "${PASS_WARN_AGE}" \
            "${username}"

        log "Password expiration policy applied: ${username}"
    fi
done < /etc/passwd

# Validation.
grep -Eq "^minlen[[:space:]]*=[[:space:]]*${MINLEN}[[:space:]]*$" "${PWQUALITY}" ||
    fail "Password minimum length validation failed."

grep -Eq '^dcredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' "${PWQUALITY}" ||
    fail "Digit requirement validation failed."

grep -Eq '^ucredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' "${PWQUALITY}" ||
    fail "Uppercase requirement validation failed."

grep -Eq '^lcredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' "${PWQUALITY}" ||
    fail "Lowercase requirement validation failed."

grep -Eq '^ocredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' "${PWQUALITY}" ||
    fail "Special-character requirement validation failed."

if [[ "${FAMILY}" == "debian" ]]; then
    grep -Eq 'pam_pwquality\.so[[:space:]]+retry=5' "${COMMON_PASSWORD}" ||
        fail "pam_pwquality retry=5 validation failed."

    grep -Eq 'pam_pwhistory\.so.*remember=5' "${COMMON_PASSWORD}" ||
        fail "Password history validation failed."
else
    authselect check >/dev/null 2>&1 ||
        fail "authselect validation failed."

    authselect current | grep -qw 'with-pwhistory' ||
        fail "authselect with-pwhistory is not enabled."

    grep -Eq 'pam_pwhistory\.so' "${SYSTEM_AUTH}" ||
        fail "pam_pwhistory is not active in system-auth."

    grep -Eq 'pam_pwhistory\.so' "${PASSWORD_AUTH}" ||
        fail "pam_pwhistory is not active in password-auth."
fi

log "Backup location: ${BACKUP_DIR}"
log "=== Password Policy Applied Successfully ==="
log "Policy: minlen=${MINLEN}, history=${HISTORY}, expiry=${PASS_MAX_DAYS}/${PASS_MIN_DAYS}/${PASS_WARN_AGE}."
