#!/usr/bin/env bash
set -Eeuo pipefail

# Ubuntu 22.04 LTS SSH hardening.
# Modifies ONLY /etc/ssh/sshd_config.
# Does NOT modify /etc/ssh/sshd_config.d/.
# Banner is intentionally not configured (N/A).
# Ubuntu 22.04/OpenSSH 8.9 uses SSH protocol 2 only, so the legacy
# "Protocol 2" directive is intentionally not added.

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_ROOT="/var/backups/ssh-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."
[[ -f "${SSHD_CONFIG}" ]] || fail "${SSHD_CONFIG} not found."

# shellcheck disable=SC1091
. /etc/os-release

[[ "${ID,,}" == "ubuntu" ]] || fail "Unsupported OS: ${PRETTY_NAME:-${ID}}"
[[ "${VERSION_ID:-}" == "22.04" ]] || fail "This script is intended for Ubuntu 22.04 LTS. Detected: ${PRETTY_NAME:-unknown}"

SSHD_BIN="$(command -v sshd || true)"
[[ -n "${SSHD_BIN}" ]] || SSHD_BIN="/usr/sbin/sshd"
[[ -x "${SSHD_BIN}" ]] || fail "sshd binary not found."

log "Detected OS: ${PRETTY_NAME}"
log "=== Applying SSH hardening directly to ${SSHD_CONFIG} ==="

mkdir -p "${BACKUP_DIR}"
cp -a "${SSHD_CONFIG}" "${BACKUP_DIR}/sshd_config"
log "Backup created: ${BACKUP_DIR}/sshd_config"

# Secure ownership and permissions.
chown root:root "${SSHD_CONFIG}"
chmod og-rwx "${SSHD_CONFIG}"

# Remove obsolete Protocol directives if present.
sed -Ei '/^[[:space:]]*Protocol[[:space:]]+/d' "${SSHD_CONFIG}"

MANAGED_KEYS='Ciphers|MACs|KexAlgorithms|LogLevel|LoginGraceTime|PermitRootLogin|MaxAuthTries|PermitEmptyPasswords|AllowTcpForwarding|X11Forwarding|ClientAliveInterval|ClientAliveCountMax|MaxStartups'
TMP="$(mktemp)"
trap 'rm -f "${TMP}" "${TMP}.new"' EXIT

# Remove active global occurrences of managed directives before the first Match block.
awk -v keys="${MANAGED_KEYS}" '
BEGIN {
    n=split(keys,a,"|")
    for (i=1;i<=n;i++) managed[a[i]]=1
}
{
    line=$0
    if (line ~ /^[[:space:]]*Match[[:space:]]+/) in_match=1
    if (!in_match) {
        stripped=line
        sub(/^[[:space:]]+/, "", stripped)
        split(stripped, f, /[[:space:]]+/)
        if (f[1] in managed) next
    }
    print line
}
' "${SSHD_CONFIG}" > "${TMP}"

# Insert the hardening policy in global context, before the first Match block.
awk '
BEGIN { inserted=0 }

function policy() {
    print ""
    print "# BEGIN MANAGED SSH HARDENING - Ubuntu 22.04"
    print "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
    print "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    print "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"
    print "LogLevel VERBOSE"
    print "LoginGraceTime 60"
    print "PermitRootLogin prohibit-password"
    print "MaxAuthTries 4"
    print "PermitEmptyPasswords no"
    print "AllowTcpForwarding no"
    print "X11Forwarding no"
    print "ClientAliveInterval 300"
    print "ClientAliveCountMax 3"
    print "MaxStartups 10:30:60"
    print "# END MANAGED SSH HARDENING"
    print ""
}

{
    if (!inserted && $0 ~ /^[[:space:]]*Match[[:space:]]+/) {
        policy()
        inserted=1
    }
    print
}

END {
    if (!inserted) policy()
}
' "${TMP}" > "${TMP}.new"

cat "${TMP}.new" > "${SSHD_CONFIG}"

# Re-apply secure ownership and permissions.
chown root:root "${SSHD_CONFIG}"
chmod 600 "${SSHD_CONFIG}"

OWNER="$(stat -c '%U:%G' "${SSHD_CONFIG}")"
MODE="$(stat -c '%a' "${SSHD_CONFIG}")"

[[ "${OWNER}" == "root:root" ]] ||
    fail "Ownership validation failed: ${OWNER}"

[[ "${MODE}" == "600" ]] ||
    fail "Permission validation failed: ${MODE}"

# Validate syntax before reload.
"${SSHD_BIN}" -t ||
    fail "sshd configuration syntax validation failed. SSH service was NOT reloaded."

EFFECTIVE="$("${SSHD_BIN}" -T 2>/dev/null)"

check_effective() {
    local regex="$1"
    local description="$2"

    grep -Eq "${regex}" <<< "${EFFECTIVE}" ||
        fail "Effective ${description} does not match. Check existing /etc/ssh/sshd_config.d/*.conf."

    log "Effective ${description}: OK"
}

check_effective '^ciphers aes128-ctr,aes192-ctr,aes256-ctr$' \
    "Ciphers"

check_effective '^macs hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256$' \
    "MACs"

check_effective '^kexalgorithms curve25519-sha256@libssh\.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256$' \
    "KexAlgorithms"

# LogLevel can be rendered as VERBOSE/verbose depending on OpenSSH output.
if grep -Eqi '^loglevel[[:space:]]+verbose$' <<< "${EFFECTIVE}"; then
    log "Effective LogLevel: OK"
else
    fail "Effective LogLevel does not match. Check existing /etc/ssh/sshd_config.d/*.conf."
fi

check_effective '^logingracetime 60$' \
    "LoginGraceTime"

check_effective '^permitrootlogin (prohibit-password|without-password)$' \
    "PermitRootLogin"

check_effective '^maxauthtries 4$' \
    "MaxAuthTries"

check_effective '^permitemptypasswords no$' \
    "PermitEmptyPasswords"

check_effective '^allowtcpforwarding no$' \
    "AllowTcpForwarding"

check_effective '^x11forwarding no$' \
    "X11Forwarding"

check_effective '^clientaliveinterval 300$' \
    "ClientAliveInterval"

check_effective '^clientalivecountmax 3$' \
    "ClientAliveCountMax"

check_effective '^maxstartups 10:30:60$' \
    "MaxStartups"

# Reload SSH only after all checks pass.
systemctl reload ssh ||
    fail "Failed to reload ssh service."

systemctl is-active --quiet ssh ||
    fail "ssh service is not active after reload."

echo
echo "============================================================"
echo "SSH hardening applied successfully"
echo "File       : ${SSHD_CONFIG}"
echo "Owner      : $(stat -c '%U:%G' "${SSHD_CONFIG}")"
echo "Permission : $(stat -c '%a' "${SSHD_CONFIG}")"
echo "Backup     : ${BACKUP_DIR}/sshd_config"
echo "============================================================"
echo
echo "[IMPORTANT] Do NOT close the current SSH session yet."
echo "Open a second terminal and verify that SSH login still works."
