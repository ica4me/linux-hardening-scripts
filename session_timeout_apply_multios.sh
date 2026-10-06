#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform SSH/session policy.
# Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN="${SSHD_DROPIN_DIR}/00-dbalance-session-security.conf"
TIMEOUT_FILE="/etc/profile.d/99-session-timeout.sh"

CLIENT_ALIVE_INTERVAL="${CLIENT_ALIVE_INTERVAL:-300}"
CLIENT_ALIVE_COUNT_MAX="${CLIENT_ALIVE_COUNT_MAX:-3}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-900}"

BACKUP_ROOT="/var/backups/session-timeout"
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
        SSH_SERVICE="ssh"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] ||
            fail "Unsupported Debian version: ${OS_VER}"
        SSH_SERVICE="ssh"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] ||
            fail "Unsupported RHEL version: ${OS_VER}"
        SSH_SERVICE="sshd"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        ;;
esac

[[ -f "${SSHD_CONFIG}" ]] || fail "${SSHD_CONFIG} not found."

SSHD_BIN="$(command -v sshd || true)"
[[ -n "${SSHD_BIN}" ]] || SSHD_BIN="/usr/sbin/sshd"
[[ -x "${SSHD_BIN}" ]] || fail "sshd binary not found."

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying SSH & Session Timeout Policy ==="

mkdir -p "${BACKUP_DIR}"
mkdir -p "${SSHD_DROPIN_DIR}"

cp -a "${SSHD_CONFIG}" "${BACKUP_DIR}/sshd_config"

[[ -f "${SSHD_DROPIN}" ]] &&
    cp -a "${SSHD_DROPIN}" "${BACKUP_DIR}/00-dbalance-session-security.conf"

[[ -f "${TIMEOUT_FILE}" ]] &&
    cp -a "${TIMEOUT_FILE}" "${BACKUP_DIR}/99-session-timeout.sh"

log "Backup created: ${BACKUP_DIR}"

set_sshd_value() {
    local key="$1"
    local value="$2"

    if grep -Eq "^[[:space:]#]*${key}[[:space:]]+" "${SSHD_CONFIG}"; then
        sed -Ei \
            "s|^[[:space:]#]*${key}[[:space:]]+.*$|${key} ${value}|" \
            "${SSHD_CONFIG}"
    else
        printf '\n%s %s\n' "${key}" "${value}" >> "${SSHD_CONFIG}"
    fi
}

# Keep the requested values explicit in the main sshd_config.
set_sshd_value "PasswordAuthentication" "no"
set_sshd_value "PermitRootLogin" "prohibit-password"
set_sshd_value "KbdInteractiveAuthentication" "no"
set_sshd_value "ClientAliveInterval" "${CLIENT_ALIVE_INTERVAL}"
set_sshd_value "ClientAliveCountMax" "${CLIENT_ALIVE_COUNT_MAX}"

# An early drop-in guarantees the same effective settings when vendor/cloud
# drop-ins are also present.
cat > "${SSHD_DROPIN}" <<EOF
# DBalance SSH/session security policy
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
ClientAliveInterval ${CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${CLIENT_ALIVE_COUNT_MAX}
EOF

# Interactive shell idle timeout.
cat > "${TIMEOUT_FILE}" <<EOF
# Interactive shell idle timeout
TMOUT=${SESSION_TIMEOUT}
readonly TMOUT
export TMOUT
EOF

chown root:root "${SSHD_CONFIG}" "${SSHD_DROPIN}" "${TIMEOUT_FILE}"
chmod 0600 "${SSHD_CONFIG}"
chmod 0600 "${SSHD_DROPIN}"
chmod 0644 "${TIMEOUT_FILE}"

# Validate before applying.
"${SSHD_BIN}" -t || fail "SSH configuration validation failed."

# Verify effective values before reload.
EFFECTIVE="$("${SSHD_BIN}" -T 2>/dev/null)"

grep -Eq '^passwordauthentication no$' <<< "${EFFECTIVE}" ||
    fail "Effective PasswordAuthentication is not 'no'."

grep -Eq '^permitrootlogin prohibit-password$' <<< "${EFFECTIVE}" ||
    fail "Effective PermitRootLogin is not 'prohibit-password'."

grep -Eq '^kbdinteractiveauthentication no$' <<< "${EFFECTIVE}" ||
    fail "Effective KbdInteractiveAuthentication is not 'no'."

grep -Eq "^clientaliveinterval ${CLIENT_ALIVE_INTERVAL}$" <<< "${EFFECTIVE}" ||
    fail "Effective ClientAliveInterval is incorrect."

grep -Eq "^clientalivecountmax ${CLIENT_ALIVE_COUNT_MAX}$" <<< "${EFFECTIVE}" ||
    fail "Effective ClientAliveCountMax is incorrect."

systemctl reload "${SSH_SERVICE}" ||
    fail "Failed to reload ${SSH_SERVICE}."

systemctl is-active --quiet "${SSH_SERVICE}" ||
    fail "${SSH_SERVICE} is not active."

log "Backup location: ${BACKUP_DIR}"
log "=== SSH & Session Timeout Policy Applied Successfully ==="
log "Run /root/session_timeout_verifikasi.sh"
