#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform password policy:
# Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x

MINLEN=12
HISTORY=5

# Temporary login ban.
LOCKOUT_DENY="${LOCKOUT_DENY:-5}"
LOCKOUT_TIME="${LOCKOUT_TIME:-600}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"

PWQUALITY="/etc/security/pwquality.conf"
PWHISTORY_CONF="/etc/security/pwhistory.conf"
FAILLOCK="/etc/security/faillock.conf"
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
    local file="$1" key="$2" value="$3"
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
    local file="$1" key="$2" value="$3"

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
backup_if_exists "${FAILLOCK}"
backup_if_exists "${LOGIN_DEFS}"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_PASSWORD="/etc/pam.d/common-password"
    COMMON_AUTH="/etc/pam.d/common-auth"
    COMMON_ACCOUNT="/etc/pam.d/common-account"

    backup_if_exists "${COMMON_PASSWORD}"
    backup_if_exists "${COMMON_AUTH}"
    backup_if_exists "${COMMON_ACCOUNT}"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq libpam-pwquality libpam-modules

    [[ -f "${COMMON_PASSWORD}" ]] || fail "${COMMON_PASSWORD} not found."
    [[ -f "${COMMON_AUTH}" ]] || fail "${COMMON_AUTH} not found."
    [[ -f "${COMMON_ACCOUNT}" ]] || fail "${COMMON_ACCOUNT} not found."
else
    SYSTEM_AUTH="/etc/pam.d/system-auth"
    PASSWORD_AUTH="/etc/pam.d/password-auth"

    backup_if_exists "${SYSTEM_AUTH}"
    backup_if_exists "${PASSWORD_AUTH}"

    dnf install -y -q libpwquality pam authselect

    command -v authselect >/dev/null 2>&1 ||
        fail "authselect not found."

    authselect check >/dev/null 2>&1 ||
        fail "Current authselect configuration is invalid. Fix it before applying this policy."

    authselect current >/dev/null 2>&1 ||
        fail "No active authselect profile found."
fi

# Password complexity
set_eq_value "${PWQUALITY}" "minlen" "12"
set_eq_value "${PWQUALITY}" "dcredit" "-1"
set_eq_value "${PWQUALITY}" "ucredit" "-1"
set_eq_value "${PWQUALITY}" "lcredit" "-1"
set_eq_value "${PWQUALITY}" "ocredit" "0"
set_eq_value "${PWQUALITY}" "enforcing" "1"

# Password history
if [[ "${FAMILY}" == "debian" ]]; then
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "${COMMON_PASSWORD}"; then
        sed -i \
            '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password        requisite                       pam_pwquality.so retry=3' \
            "${COMMON_PASSWORD}"
    fi

    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so' "${COMMON_PASSWORD}"; then
        sed -Ei \
            's|^[[:space:]]*password[[:space:]].*pam_pwhistory\.so.*$|password        required                        pam_pwhistory.so remember=5 use_authtok|' \
            "${COMMON_PASSWORD}"
    else
        sed -i \
            '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password        required                        pam_pwhistory.so remember=5 use_authtok' \
            "${COMMON_PASSWORD}"
    fi
else
    set_eq_value "${PWHISTORY_CONF}" "remember" "${HISTORY}"

    if ! authselect current | grep -qw 'with-pwhistory'; then
        authselect enable-feature with-pwhistory -b >/dev/null
    fi
fi

# Password never expires
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "-1"
set_space_value "${LOGIN_DEFS}" "PASS_MIN_DAYS" "0"
set_space_value "${LOGIN_DEFS}" "PASS_WARN_AGE" "-1"

UID_MIN="$(awk '$1=="UID_MIN"{print $2; exit}' "${LOGIN_DEFS}")"
UID_MIN="${UID_MIN:-1000}"

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "${uid}" -ge "${UID_MIN}" &&
          "${username}" != "nobody" &&
          "${shell}" != */nologin &&
          "${shell}" != */false ]]; then
        chage -M -1 -m 0 -W -1 "${username}"
        log "Password expiration disabled: ${username}"
    fi
done < /etc/passwd

# Temporary login ban: default 5 failures, then 10 minutes.
set_eq_value "${FAILLOCK}" "deny" "${LOCKOUT_DENY}"
set_eq_value "${FAILLOCK}" "fail_interval" "${FAIL_INTERVAL}"
set_eq_value "${FAILLOCK}" "unlock_time" "${LOCKOUT_TIME}"

if [[ "${FAMILY}" == "debian" ]]; then
    sed -i '/pam_faillock\.so/d' "${COMMON_AUTH}"

    sed -i \
        '/^[[:space:]]*auth[[:space:]].*pam_unix\.so/i auth    required                        pam_faillock.so preauth silent' \
        "${COMMON_AUTH}"

    sed -i \
        '/^[[:space:]]*auth[[:space:]].*pam_unix\.so/a auth    [default=die]                   pam_faillock.so authfail\nauth    sufficient                      pam_faillock.so authsucc' \
        "${COMMON_AUTH}"

    sed -i '/pam_faillock\.so/d' "${COMMON_ACCOUNT}"
    printf '\n# Temporary login ban policy\naccount required pam_faillock.so\n' >> "${COMMON_ACCOUNT}"
else
    if ! authselect current | grep -qw 'with-faillock'; then
        authselect enable-feature with-faillock -b >/dev/null
    fi
    authselect apply-changes >/dev/null
fi

# Basic validation
grep -Eq '^minlen[[:space:]]*=[[:space:]]*12' "${PWQUALITY}" ||
    fail "Password minimum length validation failed."

if [[ "${FAMILY}" == "debian" ]]; then
    grep -Eq 'pam_pwhistory\.so.*remember=5' "${COMMON_PASSWORD}" ||
        fail "Password history validation failed."
    grep -Eq 'pam_faillock\.so[[:space:]]+authfail' "${COMMON_AUTH}" ||
        fail "PAM faillock validation failed."
else
    authselect check >/dev/null 2>&1 ||
        fail "authselect validation failed."
    grep -Eq 'pam_pwhistory\.so' "${SYSTEM_AUTH}" ||
        fail "pam_pwhistory is not active in system-auth."
    grep -Eq 'pam_faillock\.so' "${SYSTEM_AUTH}" ||
        fail "pam_faillock is not active in system-auth."
fi

log "Backup location: ${BACKUP_DIR}"
log "=== Password Policy Applied Successfully ==="
log "Run password_policy_verifikasi.sh to verify."
