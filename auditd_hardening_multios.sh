#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform auditd hardening.
#
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# The rule layout follows the reference policy and uses separate files:
#   50-time-change.rules
#   50-identity.rules
#   50-system-locale.rules
#   50-MAC-policy.rules
#   50-logins.rules
#   50-session.rules
#   50-perm_mod.rules
#   50-access.rules
#   50-delete.rules
#   50-scope.rules
#   50-actions.rules
#
# On Ubuntu/Debian, MAC policy watches AppArmor.
# On RHEL, the MAC policy is adapted to SELinux.
#
# The script is idempotent:
# - Managed rule files are overwritten, not appended.
# - Previous aggregate rule files created by older versions are backed up
#   and removed to prevent duplicate audit rules.
# - Runtime rules are cleared before the complete persistent ruleset is loaded,
#   unless audit is immutable (enabled=2).

RULES_DIR="/etc/audit/rules.d"
BACKUP_ROOT="/var/backups/auditd-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

UID_MIN="1000"

MANAGED_FILES=(
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

OLD_AGGREGATE_FILES=(
    "50-linux-hardening.rules"
    "50-dbalance-hardening.rules"
)

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
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
        MAC_TYPE="apparmor"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] ||
            fail "Unsupported Debian version: ${OS_VER}"
        FAMILY="debian"
        MAC_TYPE="apparmor"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] ||
            fail "Unsupported RHEL version: ${OS_VER}"
        FAMILY="rhel"
        MAC_TYPE="selinux"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
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
        fail "Unsupported architecture: ${ARCH}"
        ;;
esac

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "Architecture: ${ARCH}"
log "=== Applying Auditd Hardening ==="

# Install audit framework.
if [[ "${FAMILY}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq auditd audispd-plugins
else
    dnf install -y -q audit audispd-plugins
fi

command -v auditctl >/dev/null 2>&1 || fail "auditctl not found."
command -v augenrules >/dev/null 2>&1 || fail "augenrules not found."

mkdir -p "${RULES_DIR}" "${BACKUP_DIR}"

backup_file() {
    local path="$1"
    if [[ -e "${path}" ]]; then
        cp -a "${path}" "${BACKUP_DIR}/$(basename "${path}")"
    fi
}

# Backup managed rule files.
for file in "${MANAGED_FILES[@]}"; do
    backup_file "${RULES_DIR}/${file}"
done

# Backup and remove aggregate files from older script versions.
for file in "${OLD_AGGREGATE_FILES[@]}"; do
    if [[ -e "${RULES_DIR}/${file}" ]]; then
        backup_file "${RULES_DIR}/${file}"
        rm -f "${RULES_DIR}/${file}"
        log "Removed legacy aggregate rules file: ${RULES_DIR}/${file}"
    fi
done

backup_file "/etc/audit/audit.rules"
backup_file "/etc/audit/auditd.conf"

log "Backup created: ${BACKUP_DIR}"

# Ensure paths referenced by the requested policy are available where appropriate.
# Empty files are created only for legacy audit targets that may not exist yet.
if [[ ! -e /etc/security/opasswd ]]; then
    install -o root -g root -m 0600 /dev/null /etc/security/opasswd
fi

if [[ ! -e /var/log/tallylog ]]; then
    install -o root -g root -m 0600 /dev/null /var/log/tallylog
fi

# ---------------------------------------------------------------------------
# 50-time-change.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-time-change.rules" <<'EOF'
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-time-change.rules" <<'EOF'
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
EOF
fi

cat >> "${RULES_DIR}/50-time-change.rules" <<'EOF'
-a always,exit -F arch=b64 -S clock_settime -k time-change
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-time-change.rules" <<'EOF'
-a always,exit -F arch=b32 -S clock_settime -k time-change
EOF
fi

cat >> "${RULES_DIR}/50-time-change.rules" <<'EOF'
-w /etc/localtime -p wa -k time-change
EOF

# ---------------------------------------------------------------------------
# 50-identity.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-identity.rules" <<'EOF'
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF

# ---------------------------------------------------------------------------
# 50-system-locale.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-system-locale.rules" <<'EOF'
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-system-locale.rules" <<'EOF'
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
EOF
fi

cat >> "${RULES_DIR}/50-system-locale.rules" <<'EOF'
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
EOF

if [[ -e /etc/network ]]; then
    echo '-w /etc/network -p wa -k system-locale' >> "${RULES_DIR}/50-system-locale.rules"
fi

# ---------------------------------------------------------------------------
# 50-MAC-policy.rules
# ---------------------------------------------------------------------------
if [[ "${MAC_TYPE}" == "apparmor" ]]; then
    cat > "${RULES_DIR}/50-MAC-policy.rules" <<'EOF'
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
else
    cat > "${RULES_DIR}/50-MAC-policy.rules" <<'EOF'
-w /etc/selinux/ -p wa -k MAC-policy
EOF
fi

# ---------------------------------------------------------------------------
# 50-logins.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-logins.rules" <<'EOF'
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF

# ---------------------------------------------------------------------------
# 50-session.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-session.rules" <<'EOF'
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF

# ---------------------------------------------------------------------------
# 50-perm_mod.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF
fi

cat >> "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF
fi

cat >> "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-perm_mod.rules" <<EOF
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=${UID_MIN} -F auid!=4294967295 -k perm_mod
EOF
fi

# ---------------------------------------------------------------------------
# 50-access.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-access.rules" <<EOF
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=4294967295 -k access
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-access.rules" <<EOF
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=4294967295 -k access
EOF
fi

cat >> "${RULES_DIR}/50-access.rules" <<EOF
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=4294967295 -k access
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-access.rules" <<EOF
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=4294967295 -k access
EOF
fi

# ---------------------------------------------------------------------------
# 50-delete.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-delete.rules" <<EOF
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=${UID_MIN} -F auid!=4294967295 -k delete
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-delete.rules" <<EOF
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=${UID_MIN} -F auid!=4294967295 -k delete
EOF
fi

# ---------------------------------------------------------------------------
# 50-scope.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-scope.rules" <<'EOF'
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

# ---------------------------------------------------------------------------
# 50-actions.rules
# ---------------------------------------------------------------------------
cat > "${RULES_DIR}/50-actions.rules" <<EOF
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=${UID_MIN} -F auid!=4294967295 -S execve -k actions
EOF

if (( HAS_B32 == 1 )); then
    cat >> "${RULES_DIR}/50-actions.rules" <<EOF
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=${UID_MIN} -F auid!=4294967295 -S execve -k actions
EOF
fi

# Secure all managed rule files.
for file in "${MANAGED_FILES[@]}"; do
    chown root:root "${RULES_DIR}/${file}"
    chmod 0640 "${RULES_DIR}/${file}"
done

# Compile persistent rules.
augenrules --check >/dev/null ||
    fail "Audit rule compilation check failed."

# Ensure auditd is enabled/running.
systemctl enable auditd >/dev/null 2>&1 || true
systemctl start auditd >/dev/null 2>&1 || true

systemctl is-active --quiet auditd ||
    fail "auditd service is not active."

# Apply the complete persistent ruleset idempotently.
AUDIT_ENABLED="$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2; exit}')"

if [[ "${AUDIT_ENABLED}" == "2" ]]; then
    warn "Audit rules are immutable (enabled=2)."
    warn "Persistent files were updated successfully, but runtime rules cannot be changed until reboot."
    warn "Reboot during a maintenance window, then run the verification script."
else
    auditctl -D >/dev/null 2>&1 ||
        fail "Failed to clear existing runtime audit rules."

    augenrules --load >/dev/null ||
        fail "Failed to load persistent audit rules."
fi

# Restart auditd when supported. Some distributions intentionally refuse
# manual restart of auditd; the rules have already been applied above.
if ! systemctl restart auditd >/dev/null 2>&1; then
    if command -v service >/dev/null 2>&1; then
        service auditd restart >/dev/null 2>&1 || true
    fi
fi

systemctl is-active --quiet auditd ||
    fail "auditd service is not active after configuration."

log "Backup location: ${BACKUP_DIR}"
log "=== Auditd Hardening Applied Successfully ==="
