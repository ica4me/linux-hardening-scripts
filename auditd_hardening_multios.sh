#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform auditd hardening.
# Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x

RULES_FILE="/etc/audit/rules.d/50-dbalance-hardening.rules"
AUDITD_CONF="/etc/audit/auditd.conf"

BACKUP_ROOT="/var/backups/auditd-hardening"
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

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying Auditd Hardening ==="

if [[ "${FAMILY}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq auditd audispd-plugins
else
    dnf install -y -q audit audispd-plugins
fi

command -v auditctl >/dev/null 2>&1 || fail "auditctl not found."
command -v augenrules >/dev/null 2>&1 || fail "augenrules not found."

mkdir -p /etc/audit/rules.d
mkdir -p "${BACKUP_DIR}"

[[ -f "${RULES_FILE}" ]] &&
    cp -a "${RULES_FILE}" "${BACKUP_DIR}/50-dbalance-hardening.rules"

[[ -f "${AUDITD_CONF}" ]] &&
    cp -a "${AUDITD_CONF}" "${BACKUP_DIR}/auditd.conf"

log "Backup created: ${BACKUP_DIR}"

UID_MIN="$(awk '$1=="UID_MIN"{print $2; exit}' /etc/login.defs 2>/dev/null)"
UID_MIN="${UID_MIN:-1000}"

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        AUDIT_ARCHES=("b64" "b32")
        ;;
    aarch64|arm64)
        AUDIT_ARCHES=("b64")
        ;;
    *)
        fail "Unsupported architecture: ${ARCH}"
        ;;
esac

: > "${RULES_FILE}"

cat >> "${RULES_FILE}" <<EOF
# DBalance cross-platform audit rules
# OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}
# UID_MIN: ${UID_MIN}

EOF

add_watch() {
    local path="$1"
    local perms="$2"
    local key="$3"

    if [[ -e "${path}" ]]; then
        printf -- '-w %s -p %s -k %s\n' "${path}" "${perms}" "${key}" >> "${RULES_FILE}"
    fi
}

add_rule_for_arches() {
    local syscall_list="$1"
    local extra_filters="$2"
    local key="$3"
    local arch

    for arch in "${AUDIT_ARCHES[@]}"; do
        printf -- '-a always,exit -F arch=%s -S %s %s -k %s\n' \
            "${arch}" "${syscall_list}" "${extra_filters}" "${key}" >> "${RULES_FILE}"
    done
}

# Time changes
add_rule_for_arches "adjtimex,settimeofday,clock_settime" "" "time-change"
add_watch "/etc/localtime" "wa" "time-change"

# Identity changes
add_watch "/etc/group" "wa" "identity"
add_watch "/etc/passwd" "wa" "identity"
add_watch "/etc/gshadow" "wa" "identity"
add_watch "/etc/shadow" "wa" "identity"
add_watch "/etc/security/opasswd" "wa" "identity"

# System locale and network configuration
add_rule_for_arches "sethostname,setdomainname" "" "system-locale"
add_watch "/etc/issue" "wa" "system-locale"
add_watch "/etc/issue.net" "wa" "system-locale"
add_watch "/etc/hosts" "wa" "system-locale"

if [[ "${FAMILY}" == "debian" ]]; then
    add_watch "/etc/netplan" "wa" "system-locale"
    add_watch "/etc/network" "wa" "system-locale"
else
    add_watch "/etc/NetworkManager" "wa" "system-locale"
    add_watch "/etc/sysconfig/network-scripts" "wa" "system-locale"
fi

# Mandatory access control policy
if [[ "${MAC_TYPE}" == "apparmor" ]]; then
    add_watch "/etc/apparmor" "wa" "MAC-policy"
    add_watch "/etc/apparmor.d" "wa" "MAC-policy"
else
    add_watch "/etc/selinux" "wa" "MAC-policy"
fi

# Login records
add_watch "/var/log/faillog" "wa" "logins"
add_watch "/var/log/lastlog" "wa" "logins"
add_watch "/var/log/tallylog" "wa" "logins"

# Session records
add_watch "/run/utmp" "wa" "session"
add_watch "/var/run/utmp" "wa" "session"
add_watch "/var/log/wtmp" "wa" "logins"
add_watch "/var/log/btmp" "wa" "logins"

# Permission/ownership changes
FILTER="-F auid>=${UID_MIN} -F auid!=4294967295"
add_rule_for_arches "chmod,fchmod,fchmodat" "${FILTER}" "perm_mod"
add_rule_for_arches "chown,fchown,fchownat,lchown" "${FILTER}" "perm_mod"
add_rule_for_arches "setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr" "${FILTER}" "perm_mod"

# Unauthorized file access
add_rule_for_arches "creat,open,openat,truncate,ftruncate" "-F exit=-EACCES ${FILTER}" "access"
add_rule_for_arches "creat,open,openat,truncate,ftruncate" "-F exit=-EPERM ${FILTER}" "access"

# File deletion and rename
add_rule_for_arches "unlink,unlinkat,rename,renameat" "${FILTER}" "delete"

# Sudo configuration
add_watch "/etc/sudoers" "wa" "scope"
add_watch "/etc/sudoers.d" "wa" "scope"

# Privileged commands
for arch in "${AUDIT_ARCHES[@]}"; do
    printf -- '-a always,exit -F arch=%s -C euid!=uid -F euid=0 -F auid>=%s -F auid!=4294967295 -S execve -k actions\n' \
        "${arch}" "${UID_MIN}" >> "${RULES_FILE}"
done

chown root:root "${RULES_FILE}"
chmod 0640 "${RULES_FILE}"

augenrules --check >/dev/null ||
    fail "Audit rule validation failed."

augenrules --load >/dev/null ||
    fail "Failed to load audit rules."

systemctl enable auditd >/dev/null 2>&1 || true
systemctl start auditd

systemctl is-active --quiet auditd ||
    fail "auditd is not active."

log "Backup location: ${BACKUP_DIR}"
log "=== Auditd Hardening Applied Successfully ==="
log "Run /root/auditd_verifikasi.sh"
