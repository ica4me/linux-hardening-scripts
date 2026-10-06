#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform /tmp hardening.
# Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10.x
#
# Policy:
# - /tmp uses a dedicated tmpfs mount
# - nodev, nosuid, noexec
# - mode 1777
#
# The script does not modify /etc/fstab.
# If /tmp is actively in use, the unit is enabled for the next boot
# and live activation is skipped to avoid disrupting running services.

UNIT="/etc/systemd/system/tmp.mount"
BACKUP_ROOT="/var/backups/tmp-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

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

command -v systemctl >/dev/null 2>&1 || fail "systemctl not found."
command -v findmnt >/dev/null 2>&1 || fail "findmnt not found."
command -v mountpoint >/dev/null 2>&1 || fail "mountpoint not found."
command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze not found."

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying /tmp Hardening ==="

mkdir -p "${BACKUP_DIR}"

if [[ -f "${UNIT}" || -L "${UNIT}" ]]; then
    cp -a "${UNIT}" "${BACKUP_DIR}/tmp.mount"
fi

findmnt /tmp > "${BACKUP_DIR}/tmp-findmnt-before.txt" 2>/dev/null || true
mount | grep -E ' on /tmp ' > "${BACKUP_DIR}/tmp-mount-before.txt" 2>/dev/null || true

log "Backup created: ${BACKUP_DIR}"

# If tmp.mount is masked, unmask it before installing the managed unit.
if systemctl is-enabled tmp.mount 2>/dev/null | grep -qx 'masked'; then
    log "Unmasking tmp.mount..."
    systemctl unmask tmp.mount >/dev/null 2>&1 || true
fi

cat > "${UNIT}" <<'EOF'
[Unit]
Description=Hardened Temporary Directory /tmp
Documentation=man:hier(7)
Before=local-fs.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec

[Install]
WantedBy=local-fs.target
EOF

chown root:root "${UNIT}"
chmod 0644 "${UNIT}"

systemctl daemon-reload

# Validate only the managed unit. Warnings from unrelated units do not
# invalidate tmp.mount, therefore capture output and confirm exit status.
VERIFY_OUTPUT="$(
    systemd-analyze verify "${UNIT}" 2>&1
)" || {
    printf '%s\n' "${VERIFY_OUTPUT}" >&2
    fail "tmp.mount validation failed."
}

systemctl enable tmp.mount >/dev/null 2>&1 ||
    fail "Failed to enable tmp.mount."

# If /tmp is already the desired tmpfs mount, apply options immediately.
CURRENT_FSTYPE="$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)"
CURRENT_OPTIONS="$(findmnt -n -o OPTIONS /tmp 2>/dev/null || true)"

has_mount_option() {
    local options="$1"
    local option="$2"
    grep -qw "${option}" <<< "${options//,/ }"
}

if [[ "${CURRENT_FSTYPE}" == "tmpfs" ]] &&
   has_mount_option "${CURRENT_OPTIONS}" "nodev" &&
   has_mount_option "${CURRENT_OPTIONS}" "nosuid" &&
   has_mount_option "${CURRENT_OPTIONS}" "noexec"; then

    chmod 1777 /tmp
    chown root:root /tmp
    log "/tmp is already a hardened tmpfs mount."
    log "=== /tmp Hardening Applied Successfully ==="
    log "Run /root/tmp_hardening_verifikasi.sh"
    exit 0
fi

# Install lsof only for a safe live-use check.
if ! command -v lsof >/dev/null 2>&1; then
    log "Installing lsof for safe /tmp live-use detection..."
    if [[ "${FAMILY}" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq lsof
    else
        dnf install -y -q lsof
    fi
fi

# Do not mount over /tmp while processes have open objects there.
TMP_IN_USE=0
if lsof +D /tmp 2>/dev/null | tail -n +2 | grep -q .; then
    TMP_IN_USE=1
fi

if (( TMP_IN_USE == 1 )); then
    warn "/tmp is currently in use."
    warn "tmp.mount is enabled for the next boot."
    warn "Live activation skipped to avoid disrupting running services."
    warn "Reboot during a maintenance window, then run the verification script."
    exit 0
fi

# Activate immediately only when it is safe to do so.
systemctl start tmp.mount ||
    fail "Failed to start tmp.mount."

mountpoint -q /tmp ||
    fail "/tmp is not a dedicated mount."

chmod 1777 /tmp
chown root:root /tmp

log "=== /tmp Hardening Applied Successfully ==="
log "Run /root/tmp_hardening_verifikasi.sh"
