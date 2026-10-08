#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform Account Lockout policy.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Default policy:
# deny=3
# fail_interval=900
# unlock_time=1800
#
# Result:
# - 3 failed attempts inside 15 minutes
# - temporary lock for 30 minutes
#
# Password complexity/history/expiry are intentionally handled separately.

LOCKOUT_DENY="${LOCKOUT_DENY:-3}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
UNLOCK_TIME="${UNLOCK_TIME:-1800}"

FAILLOCK_CONF="/etc/security/faillock.conf"
BACKUP_ROOT="/var/backups/account-lockout"
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
log "=== Applying Account Lockout Policy ==="

mkdir -p "${BACKUP_DIR}"

backup_if_exists() {
    local file="$1"
    if [[ -e "${file}" ]]; then
        cp -a "${file}" "${BACKUP_DIR}/$(basename "${file}")"
    fi
}

set_value() {
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

backup_if_exists "${FAILLOCK_CONF}"

if [[ "${FAMILY}" == "debian" ]]; then
    COMMON_AUTH="/etc/pam.d/common-auth"
    COMMON_ACCOUNT="/etc/pam.d/common-account"

    backup_if_exists "${COMMON_AUTH}"
    backup_if_exists "${COMMON_ACCOUNT}"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq libpam-modules

    [[ -f "${COMMON_AUTH}" ]] || fail "${COMMON_AUTH} not found."
    [[ -f "${COMMON_ACCOUNT}" ]] || fail "${COMMON_ACCOUNT} not found."

    PAM_FAILLOCK="$(
        find /lib /usr/lib -type f -name pam_faillock.so -print -quit 2>/dev/null
    )"

    [[ -n "${PAM_FAILLOCK}" ]] ||
        fail "pam_faillock.so not found."
else
    SYSTEM_AUTH="/etc/pam.d/system-auth"
    PASSWORD_AUTH="/etc/pam.d/password-auth"

    backup_if_exists "${SYSTEM_AUTH}"
    backup_if_exists "${PASSWORD_AUTH}"

    dnf install -y -q pam authselect

    command -v authselect >/dev/null 2>&1 ||
        fail "authselect not found."

    authselect check >/dev/null 2>&1 ||
        fail "Current authselect configuration is invalid."

    authselect current >/dev/null 2>&1 ||
        fail "No active authselect profile found."
fi

set_value "${FAILLOCK_CONF}" "deny" "${LOCKOUT_DENY}"
set_value "${FAILLOCK_CONF}" "fail_interval" "${FAIL_INTERVAL}"
set_value "${FAILLOCK_CONF}" "unlock_time" "${UNLOCK_TIME}"

if [[ "${FAMILY}" == "debian" ]]; then
    sed -i '/pam_faillock\.so/d' "${COMMON_AUTH}"
    sed -i '/pam_faillock\.so/d' "${COMMON_ACCOUNT}"

    sed -i \
        '/^[[:space:]]*auth[[:space:]].*pam_unix\.so/i\
auth    required                        pam_faillock.so preauth' \
        "${COMMON_AUTH}"

    sed -i \
        '/^[[:space:]]*auth[[:space:]].*pam_unix\.so/a\
auth    [default=die]                   pam_faillock.so authfail\
\nauth    sufficient                      pam_faillock.so authsucc' \
        "${COMMON_AUTH}"

    if grep -Eq '^[[:space:]]*# end of pam-auth-update config' "${COMMON_ACCOUNT}"; then
        sed -i \
            '/^[[:space:]]*# end of pam-auth-update config/i\
account required                        pam_faillock.so' \
            "${COMMON_ACCOUNT}"
    else
        printf '\naccount required                        pam_faillock.so\n' \
            >> "${COMMON_ACCOUNT}"
    fi
else
    if ! authselect current | grep -qw 'with-faillock'; then
        authselect enable-feature with-faillock -b >/dev/null
    fi

    authselect apply-changes >/dev/null
fi

# Validation.
[[ "$(awk -F= '/^[[:space:]]*deny[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}' "${FAILLOCK_CONF}")" == "${LOCKOUT_DENY}" ]] ||
    fail "deny validation failed."

[[ "$(awk -F= '/^[[:space:]]*fail_interval[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}' "${FAILLOCK_CONF}")" == "${FAIL_INTERVAL}" ]] ||
    fail "fail_interval validation failed."

[[ "$(awk -F= '/^[[:space:]]*unlock_time[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}' "${FAILLOCK_CONF}")" == "${UNLOCK_TIME}" ]] ||
    fail "unlock_time validation failed."

if [[ "${FAMILY}" == "debian" ]]; then
    grep -Eq 'pam_faillock\.so[[:space:]]+preauth' "${COMMON_AUTH}" ||
        fail "pam_faillock preauth validation failed."

    grep -Eq 'pam_faillock\.so[[:space:]]+authfail' "${COMMON_AUTH}" ||
        fail "pam_faillock authfail validation failed."

    grep -Eq 'pam_faillock\.so[[:space:]]+authsucc' "${COMMON_AUTH}" ||
        fail "pam_faillock authsucc validation failed."

    grep -Eq \
        '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so' \
        "${COMMON_ACCOUNT}" ||
        fail "pam_faillock account validation failed."
else
    authselect check >/dev/null 2>&1 ||
        fail "authselect validation failed."

    authselect current | grep -qw 'with-faillock' ||
        fail "authselect with-faillock is not enabled."

    grep -Eq 'pam_faillock\.so' "${SYSTEM_AUTH}" ||
        fail "pam_faillock missing from system-auth."

    grep -Eq 'pam_faillock\.so' "${PASSWORD_AUTH}" ||
        fail "pam_faillock missing from password-auth."
fi

log "Backup location: ${BACKUP_DIR}"
log "=== Account Lockout Policy Applied Successfully ==="
log "Policy: ${LOCKOUT_DENY} failures within ${FAIL_INTERVAL}s -> ${UNLOCK_TIME}s temporary ban."
